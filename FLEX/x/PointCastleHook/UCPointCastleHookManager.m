#import "UCPointCastleHookManager.h"
#import "UCDartMemoryScanner.h"
#import "UCAESKeyValidator.h"
#import "../Decrypt/DatabaseManager.h"
#import <pthread.h>

// 扫描去抖间隔（秒）
static const NSTimeInterval kScanDebounceInterval = 5.0;

// 扫描锁
static pthread_mutex_t gScanLock = PTHREAD_MUTEX_INITIALIZER;
static NSTimeInterval gLastScanTime = 0;
static BOOL gIsScanning = NO;

// ─── 自定义 NSURLProtocol ───
// 直接注册一个 NSURLProtocol 子类，拦截所有 HTTP/HTTPS 响应，
// 不依赖 URLCapture.m 的 NSURLSession hook（Flutter 的 dart:io
// 在 iOS 上的 NSURLSession 用法可能没被 URLCapture.m 覆盖到）。
//
// 注意：这个 protocol 只"观察"响应，不修改也不拦截，
// 请求仍然由原来的 NSURLSession/NSURLConnection 处理。
//
// 实现方式：用一个临时的 NSURLSessionDataTask 来获取响应数据，
// 然后调用 client 回传。这样既能拿到响应明文，又不改变行为。

@interface UCPointCastleURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *dataTask;
@property (nonatomic, strong) NSMutableData *responseData;
@end

@implementation UCPointCastleURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    // 只处理 http/https
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
    // 防止递归
    if ([NSURLProtocol propertyForKey:@"UCPointCastleHandled" inRequest:request]) {
        return NO;
    }
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    NSMutableURLRequest *mutableReq = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"UCPointCastleHandled" inRequest:mutableReq];

    self.responseData = [NSMutableData data];

    // 用共享 session 发请求，走系统默认配置
    NSURLSession *session = [NSURLSession sharedSession];
    self.dataTask = [session dataTaskWithRequest:mutableReq
                               completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            [self.responseData appendData:data];
        }

        // 检测 MDTV 响应
        if (data.length > 0 && response) {
            [UCPointCastleHookManager handleDecryptedResponse:data];
        }

        // 回传给 client
        if (response) {
            [self.client URLProtocol:self didReceiveResponse:response
                   cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        }
        if (data) {
            [self.client URLProtocol:self didLoadData:data];
        }
        if (error) {
            [self.client URLProtocol:self didFailWithError:error];
        } else {
            [self.client URLProtocolDidFinishLoading:self];
        }
    }];
    [self.dataTask resume];
}

- (void)stopLoading {
    [self.dataTask cancel];
    self.dataTask = nil;
    self.responseData = nil;
}

@end

// ─── 主管理器 ───

@interface UCPointCastleHookManager ()
@end

@implementation UCPointCastleHookManager

+ (instancetype)sharedManager {
    static UCPointCastleHookManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

#pragma mark - 安装 Hooks

- (void)installHooks {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 注册自定义 NSURLProtocol，拦截所有 HTTP/HTTPS 响应
        [NSURLProtocol registerClass:[UCPointCastleURLProtocol class]];

        // 同时修改 default 和 ephemeral session 配置，
        // 确保 NSURLSession 也会经过我们的 protocol
        Class configCls = [NSURLSessionConfiguration class];
        SEL defaultSel = @selector(defaultSessionConfiguration);
        SEL ephemeralSel = @selector(ephemeralSessionConfiguration);

        Method defaultMethod = class_getClassMethod(configCls, defaultSel);
        Method ephemeralMethod = class_getClassMethod(configCls, ephemeralSel);

        if (defaultMethod) {
            IMP originalImp = method_getImplementation(defaultMethod);
            typedef NSURLSessionConfiguration *(*ConfigFunc)(id, SEL);
            ConfigFunc original = (ConfigFunc)originalImp;

            IMP newImp = imp_implementationWithBlock(^NSURLSessionConfiguration *(id self) {
                NSURLSessionConfiguration *config = original(self, defaultSel);
                NSMutableArray *protocols = [config.protocolClasses mutableCopy] ?: [NSMutableArray array];
                if (![protocols containsObject:[UCPointCastleURLProtocol class]]) {
                    [protocols insertObject:[UCPointCastleURLProtocol class] atIndex:0];
                    config.protocolClasses = protocols;
                }
                return config;
            });
            method_setImplementation(defaultMethod, newImp);
        }

        if (ephemeralMethod) {
            IMP originalImp = method_getImplementation(ephemeralMethod);
            typedef NSURLSessionConfiguration *(*ConfigFunc)(id, SEL);
            ConfigFunc original = (ConfigFunc)originalImp;

            IMP newImp = imp_implementationWithBlock(^NSURLSessionConfiguration *(id self) {
                NSURLSessionConfiguration *config = original(self, ephemeralSel);
                NSMutableArray *protocols = [config.protocolClasses mutableCopy] ?: [NSMutableArray array];
                if (![protocols containsObject:[UCPointCastleURLProtocol class]]) {
                    [protocols insertObject:[UCPointCastleURLProtocol class] atIndex:0];
                    config.protocolClasses = protocols;
                }
                return config;
            });
            method_setImplementation(ephemeralMethod, newImp);
        }

        NSString *log = @"[PointCastleHook] NSURLProtocol hooks installed";
        NSLog(@"%@", log);
        [[DatabaseManager sharedManager] insertLogText:log];
    });
}

#pragma mark - 响应检测入口

+ (void)handleDecryptedResponse:(NSData *)body {
    if (!body || body.length < 64) return;

    // 只解析尾部 8KB，避免为大响应分配巨大 NSString
    static const NSUInteger kParseWindowSize = 8 * 1024;
    NSUInteger parseLen = MIN(body.length, kParseWindowSize);
    NSData *tailData = [body subdataWithRange:NSMakeRange(body.length - parseLen, parseLen)];

    NSString *text = [[NSString alloc] initWithData:tailData encoding:NSUTF8StringEncoding];
    if (!text) return;

    // 查找 MDTV 响应特征：{"suffix":"...","data":"..."}
    NSRange dataRange = [text rangeOfString:@"\"data\"" options:NSBackwardsSearch];
    if (dataRange.location == NSNotFound) return;

    NSRange suffixRange = [text rangeOfString:@"\"suffix\"" options:NSBackwardsSearch];
    if (suffixRange.location == NSNotFound) return;

    // 提取 suffix（6 位 hex）
    NSUInteger suffixSearchStart = suffixRange.location;
    NSUInteger suffixSearchLen = MIN(64, text.length - suffixSearchStart);
    NSString *suffix = [self extractJSONStringValue:text key:@"suffix"
                                        searchRange:NSMakeRange(suffixSearchStart, suffixSearchLen)];

    NSUInteger dataSearchStart = dataRange.location;
    NSUInteger dataSearchLen = MIN(2048, text.length - dataSearchStart);
    NSString *b64Data = [self extractJSONStringValue:text key:@"data"
                                        searchRange:NSMakeRange(dataSearchStart, dataSearchLen)];

    if (!suffix || suffix.length != 6 || !b64Data || b64Data.length < 16) return;

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] captured response suffix=%@ dataLen=%lu",
                     suffix, (unsigned long)b64Data.length];
    NSLog(@"%@", log);
    [[DatabaseManager sharedManager] insertLogText:log];

    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:b64Data
                                                             options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!cipherData || cipherData.length == 0) return;

    NSArray<NSData *> *ivCandidates = [self ivCandidatesFromSuffix:suffix];

    [self triggerScanAndValidateWithCiphertext:cipherData ivCandidates:ivCandidates];
}

+ (nullable NSString *)extractJSONStringValue:(NSString *)json key:(NSString *)key searchRange:(NSRange)range {
    if (!json || !key) return nil;
    NSRange keyRange = [json rangeOfString:[NSString stringWithFormat:@"\"%@\"", key] options:0 range:range];
    if (keyRange.location == NSNotFound) return nil;

    NSUInteger start = NSMaxRange(keyRange);
    NSUInteger len = json.length;
    while (start < len && [[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:[json characterAtIndex:start]]) start++;
    if (start >= len || [json characterAtIndex:start] != ':') return nil;
    start++;
    while (start < len && [[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:[json characterAtIndex:start]]) start++;
    if (start >= len || [json characterAtIndex:start] != '"') return nil;
    start++;

    NSMutableString *value = [NSMutableString string];
    for (NSUInteger i = start; i < len; i++) {
        unichar c = [json characterAtIndex:i];
        if (c == '"') break;
        if (c == '\\' && i + 1 < len) {
            [value appendFormat:@"%C", [json characterAtIndex:++i]];
        } else {
            [value appendFormat:@"%C", c];
        }
    }
    return value.length > 0 ? value : nil;
}

+ (NSArray<NSData *> *)ivCandidatesFromSuffix:(NSString *)suffix {
    NSMutableArray<NSData *> *ivs = [NSMutableArray array];

    // 1. suffix 6 位 hex -> 3 字节，前面补 13 个 0x00，共 16 字节
    NSString *hex = [suffix lowercaseString];
    NSMutableData *iv1 = [NSMutableData dataWithLength:16];
    memset(iv1.mutableBytes, 0, 16);
    for (NSUInteger i = 0; i < hex.length; i++) {
        char c = [hex characterAtIndex:i];
        int val = 0;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        NSUInteger byteIdx = 13 + i / 2;
        uint8_t *bytes = (uint8_t *)iv1.mutableBytes;
        if (i % 2 == 0) bytes[byteIdx] |= (val << 4);
        else bytes[byteIdx] |= val;
    }
    [ivs addObject:iv1];

    // 2. suffix 直接 UTF-8 编码后补零到 16 字节
    NSData *suffixData = [suffix dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *iv2 = [NSMutableData dataWithLength:16];
    memset(iv2.mutableBytes, 0, 16);
    memcpy(iv2.mutableBytes, suffixData.bytes, MIN(suffixData.length, 16));
    [ivs addObject:iv2];

    // 3. 全零 IV
    [ivs addObject:[NSMutableData dataWithLength:16]];

    return ivs;
}

#pragma mark - 扫描 + 验证

+ (void)triggerScanAndValidateWithCiphertext:(NSData *)ciphertext ivCandidates:(NSArray<NSData *> *)ivCandidates {
    pthread_mutex_lock(&gScanLock);
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (gIsScanning || now - gLastScanTime < kScanDebounceInterval) {
        pthread_mutex_unlock(&gScanLock);
        return;
    }
    gIsScanning = YES;
    gLastScanTime = now;
    pthread_mutex_unlock(&gScanLock);

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] start scan for ciphertext length=%lu",
                     (unsigned long)ciphertext.length];
    NSLog(@"%@", log);
    [[DatabaseManager sharedManager] insertLogText:log];

    [[UCDartMemoryScanner sharedScanner] scanForAESKeyCandidates:100 completion:^(NSArray<NSData *> *candidates) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [self validateCandidates:candidates ciphertext:ciphertext ivCandidates:ivCandidates];

            pthread_mutex_lock(&gScanLock);
            gIsScanning = NO;
            pthread_mutex_unlock(&gScanLock);
        });
    }];
}

+ (void)validateCandidates:(NSArray<NSData *> *)candidates
               ciphertext:(NSData *)ciphertext
             ivCandidates:(NSArray<NSData *> *)ivCandidates {
    if (candidates.count == 0 || ivCandidates.count == 0) return;

    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSMutableSet<NSString *> *foundKeys = [NSMutableSet set];

    for (NSData *key in candidates) {
        for (NSData *iv in ivCandidates) {
            NSDictionary *result = [UCAESKeyValidator validateKeyAcrossModes:key ciphertext:ciphertext iv:iv];
            if (!result) continue;

            NSString *hexKey = [self hexStringFromData:key];
            if ([foundKeys containsObject:hexKey]) continue;
            [foundKeys addObject:hexKey];

            NSString *mode = result[@"mode"] ?: @"unknown";
            NSData *plain = result[@"plaintext"];
            NSString *plainText = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding] ?: @"(binary)";
            NSString *entry = [NSString stringWithFormat:
                               @"KEY=%@\nMODE=%@\nIV=%@\nPLAIN=%@",
                               hexKey, mode, [self hexStringFromData:iv],
                               [plainText substringToIndex:MIN(plainText.length, 500)]];

            [[DatabaseManager sharedManager] insertPointCastleKey:hexKey bundleID:bundleID detail:entry];

            NSString *log = [NSString stringWithFormat:@"[PointCastleHook] FOUND key=%@ mode=%@", hexKey, mode];
            NSLog(@"%@", log);
            [[DatabaseManager sharedManager] insertLogText:log];
        }
    }
}

#pragma mark - 手动触发（调试用）

- (void)triggerValidationWithResponseBody:(NSData *)responseBody {
    if (!responseBody || responseBody.length == 0) return;
    [UCPointCastleHookManager handleDecryptedResponse:responseBody];
}

#pragma mark - 工具方法

+ (NSString *)hexStringFromData:(NSData *)data {
    if (!data || data.length == 0) return @"";
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

@end