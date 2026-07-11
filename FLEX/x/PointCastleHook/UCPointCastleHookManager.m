#import "UCPointCastleHookManager.h"
#import "UCDartMemoryScanner.h"
#import "UCAESKeyValidator.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/fishhook.h"
#import <dlfcn.h>
#import <pthread.h>

// 响应体缓存阈值
static const NSUInteger kMaxResponseBuffer = 64 * 1024;  // 64KB

// 扫描去抖间隔（秒）
static const NSTimeInterval kScanDebounceInterval = 5.0;

// 扫描锁
static pthread_mutex_t gScanLock = PTHREAD_MUTEX_INITIALIZER;
static NSTimeInterval gLastScanTime = 0;
static BOOL gIsScanning = NO;

// ─── SSL_read hook ───
// BoringSSL 的 SSL_read 返回解密后的明文数据。
// POSIX recv/recvmsg 在 HTTPS 场景下返回的是 TLS 密文，JSON 解析永远匹配不到。
// 因此改用 SSL_read，在 TLS 解密后直接获取 HTTP 明文。
static int (*orig_SSL_read)(void *ssl, void *buf, int num) = NULL;

// 每个 SSL 连接的响应体缓冲（key = NSValue wrapping SSL*）
static NSMutableDictionary<NSValue *, NSMutableData *> *gResponseBuffers = nil;
static NSMutableDictionary<NSValue *, NSDate *> *gSSLActivity = nil;
static dispatch_queue_t gHookQueue = nil;
static BOOL gHooksInstalled = NO;

@interface UCPointCastleHookManager ()
@end

@implementation UCPointCastleHookManager

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gResponseBuffers = [NSMutableDictionary dictionary];
        gSSLActivity = [NSMutableDictionary dictionary];
        gHookQueue = dispatch_queue_create("com.flex.pointycastle.hook", DISPATCH_QUEUE_SERIAL);
    });
}

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
    if (gHooksInstalled) {
        NSLog(@"[PointCastleHook] hooks already installed, skipping");
        return;
    }

    // 使用 fishhook 拦截 BoringSSL 的 SSL_read
    // SSL_read 返回 TLS 解密后的明文，比 POSIX socket hook 更适合 HTTPS 场景
    struct rebinding rebindings[] = {
        {"SSL_read", hooked_SSL_read, (void **)&orig_SSL_read},
    };

    int count = sizeof(rebindings) / sizeof(rebindings[0]);
    int result = rebind_symbols(rebindings, count);

    NSUInteger success = 0;
    if (orig_SSL_read) success++;

    // 兜底：dlsym
    if (!orig_SSL_read) {
        orig_SSL_read = dlsym(RTLD_DEFAULT, "SSL_read");
        if (orig_SSL_read) success++;
    }

    NSString *log = [NSString stringWithFormat:
                     @"[PointCastleHook] SSL_read hook installed: %lu/%d (rebind=%d)",
                     (unsigned long)success, count, result];
    NSLog(@"%@", log);
    [[DatabaseManager sharedManager] insertLogText:log];

    gHooksInstalled = YES;
}

#pragma mark - SSL_read Hook

static int hooked_SSL_read(void *ssl, void *buf, int num) {
    int ret = orig_SSL_read ? orig_SSL_read(ssl, buf, num) : -1;

    if (ret > 0 && buf) {
        NSData *chunk = [NSData dataWithBytes:buf length:(NSUInteger)ret];
        [UCPointCastleHookManager handleSSLReadData:chunk sslContext:ssl];
    }

    return ret;
}

#pragma mark - 数据处理

+ (void)handleSSLReadData:(NSData *)data sslContext:(void *)ssl {
    if (!data || data.length == 0) return;

    [self cleanupStaleEntries];

    // SSL_read 返回的是解密后的明文（HTTP 响应），直接缓冲即可
    // 不需要 isLikelyTextData 预筛，因为解密后就是文本
    dispatch_async(gHookQueue, ^{
        NSValue *sslKey = [NSValue valueWithPointer:ssl];
        gSSLActivity[sslKey] = [NSDate date];

        NSMutableData *buffer = gResponseBuffers[sslKey];
        if (!buffer) {
            buffer = [NSMutableData data];
            gResponseBuffers[sslKey] = buffer;
        }
        [buffer appendData:data];

        if (buffer.length > kMaxResponseBuffer) {
            buffer.length = kMaxResponseBuffer;
        }

        [self tryParseResponseBuffer:buffer sslKey:sslKey];
    });
}

+ (void)tryParseResponseBuffer:(NSMutableData *)buffer sslKey:(NSValue *)sslKey {
    if (buffer.length < 64) return;

    gSSLActivity[sslKey] = [NSDate date];

    // 只解析尾部 8KB
    static const NSUInteger kParseWindowSize = 8 * 1024;
    NSUInteger parseLen = MIN(buffer.length, kParseWindowSize);
    NSData *tailData = [buffer subdataWithRange:NSMakeRange(buffer.length - parseLen, parseLen)];

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

    // 清除缓冲避免重复触发
    [buffer setLength:0];

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

#pragma mark - 过期 buffer 清理

+ (void)cleanupStaleEntries {
    dispatch_async(gHookQueue, ^{
        NSDate *now = [NSDate date];
        NSArray<NSValue *> *keys = [gSSLActivity allKeys];

        BOOL needCleanup = (keys.count > 50);
        for (NSValue *sslKey in keys) {
            NSDate *last = gSSLActivity[sslKey];
            if (needCleanup || !last || [now timeIntervalSinceDate:last] > 30.0) {
                [gResponseBuffers removeObjectForKey:sslKey];
                [gSSLActivity removeObjectForKey:sslKey];
            }
        }
    });
}

#pragma mark - 手动触发（调试用）

- (void)triggerValidationWithResponseBody:(NSData *)responseBody {
    if (!responseBody || responseBody.length == 0) return;
    // 直接用 -1 的 fd，走旧逻辑（保留兼容性，现在已废弃 fd 过滤）
    [UCPointCastleHookManager handleSSLReadData:responseBody sslContext:(void *)0x1];
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