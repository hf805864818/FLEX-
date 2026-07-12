#import "UCPointCastleHookManager.h"
#import "UCDartMemoryScanner.h"
#import "UCAESKeyValidator.h"
#import "../Decrypt/DatabaseManager.h"
#import <objc/runtime.h>
#import <pthread.h>

// 扫描去抖间隔（秒）
static const NSTimeInterval kScanDebounceInterval = 5.0;

// 扫描锁
static pthread_mutex_t gScanLock = PTHREAD_MUTEX_INITIALIZER;
static NSTimeInterval gLastScanTime = 0;
static BOOL gIsScanning = NO;

// ============================================================
//  Delegate 代理 — 在 NSURLSession 和原始 delegate 之间插入
//  拦截 didReceiveData / didCompleteWithError 获取明文响应
//  其他所有 delegate 方法透明转发给原始 delegate
// ============================================================

@interface UCPointCastleDelegateProxy : NSObject <NSURLSessionDataDelegate, NSURLSessionTaskDelegate>
@property (nonatomic, weak, readonly) id originalDelegate;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSMutableData *> *taskDataMap;
@property (nonatomic, strong) NSLock *dataLock;
- (instancetype)initWithOriginalDelegate:(id)delegate;
@end

@implementation UCPointCastleDelegateProxy

- (instancetype)initWithOriginalDelegate:(id)delegate {
    self = [super init];
    if (self) {
        _originalDelegate = delegate;
        _taskDataMap = [NSMutableDictionary dictionary];
        _dataLock = [[NSLock alloc] init];
    }
    return self;
}

/// 所有未直接实现的方法转发给原始 delegate
- (id)forwardingTargetForSelector:(SEL)aSelector {
    if ([self.originalDelegate respondsToSelector:aSelector]) {
        return self.originalDelegate;
    }
    return nil;
}

- (BOOL)respondsToSelector:(SEL)aSelector {
    if (aSelector == @selector(URLSession:dataTask:didReceiveData:) ||
        aSelector == @selector(URLSession:task:didCompleteWithError:)) {
        return YES;
    }
    return [self.originalDelegate respondsToSelector:aSelector] || [super respondsToSelector:aSelector];
}

/// 拦截 didReceiveData — 累积响应数据
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    if (data.length > 0) {
        [self.dataLock lock];
        NSNumber *key = @(dataTask.taskIdentifier);
        NSMutableData *accum = self.taskDataMap[key];
        if (!accum) {
            accum = [NSMutableData data];
            self.taskDataMap[key] = accum;
        }
        // 限制单条响应最多 512KB，避免内存爆炸
        if (accum.length < 512 * 1024) {
            NSUInteger remain = 512 * 1024 - accum.length;
            [accum appendData:[data subdataWithRange:NSMakeRange(0, MIN(remain, data.length))]];
        }
        [self.dataLock unlock];
    }

    // 转发给原始 delegate
    if ([self.originalDelegate respondsToSelector:_cmd]) {
        [self.originalDelegate URLSession:session dataTask:dataTask didReceiveData:data];
    }
}

/// 拦截 didCompleteWithError — 响应完成，触发密钥检测
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    [self.dataLock lock];
    NSNumber *key = @(task.taskIdentifier);
    NSMutableData *accum = self.taskDataMap[key];
    [self.taskDataMap removeObjectForKey:key];
    [self.dataLock unlock];

    // 只在成功且有数据时触发检测
    if (!error && accum.length > 0) {
        [UCPointCastleHookManager handleDecryptedResponse:accum];
    }

    // 转发给原始 delegate
    if ([self.originalDelegate respondsToSelector:_cmd]) {
        [self.originalDelegate URLSession:session task:task didCompleteWithError:error];
    }
}

@end

// ============================================================
//  保存原始 IMP（避免与 URLCapture.m 的 key 冲突，使用全局变量）
// ============================================================

static id (*gOriginalInitIMP)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *) = NULL;
static NSURLSession *(*gOriginalSessionFactoryIMP)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *) = NULL;

// ============================================================
//  Hook 实现
// ============================================================

/// ── Hook 1: -[NSURLSession initWithConfiguration:delegate:delegateQueue:] ──
/// 如果 Flutter 直接调用 init 方法（不走类方法），这里拦截
static id UCPCHookedInitWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *config,
                                     id delegate, NSOperationQueue *queue) {
    if (delegate && ![delegate isKindOfClass:[UCPointCastleDelegateProxy class]]) {
        UCPointCastleDelegateProxy *proxy = [[UCPointCastleDelegateProxy alloc] initWithOriginalDelegate:delegate];
        delegate = (id)proxy;
    }

    // 调用"原始"IMP — 可能是 URLCapture.m 的 hook，也可能是真正的原始实现
    // 无论是哪种，我们的代理 delegate 都会被正确传递下去
    return gOriginalInitIMP(self, _cmd, config, delegate, queue);
}

/// ── Hook 2: +[NSURLSession sessionWithConfiguration:delegate:delegateQueue:] ──
/// 这是 NSURLSession 的工厂方法，Flutter dart:io 使用此方法创建 session
static NSURLSession *UCPCHookedSessionFactory(id self, SEL _cmd, NSURLSessionConfiguration *config,
                                                id delegate, NSOperationQueue *queue) {
    if (delegate && ![delegate isKindOfClass:[UCPointCastleDelegateProxy class]]) {
        UCPointCastleDelegateProxy *proxy = [[UCPointCastleDelegateProxy alloc] initWithOriginalDelegate:delegate];
        delegate = (id)proxy;
    }

    return gOriginalSessionFactoryIMP(self, _cmd, config, delegate, queue);
}

// ============================================================
//  主管理器
// ============================================================

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
        Class sessionCls = [NSURLSession class];

        // ─── Hook 1: 实例方法 initWithConfiguration:delegate:delegateQueue: ───
        // 保存当前 IMP（可能是 URLCapture.m 的 hook，也可能是真正的原始实现），
        // 然后替换为我们的实现。这样我们的 hook 会在 URLCapture 的 hook 之后运行，
        // URLCapture 仍然能正常工作（它先收到原始 delegate，hook 其方法，
        // 然后我们的 hook 把 delegate 换成代理后再调用 init）。
        {
            SEL sel = @selector(initWithConfiguration:delegate:delegateQueue:);
            Method method = class_getInstanceMethod(sessionCls, sel);
            if (method) {
                gOriginalInitIMP = (id (*)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *))
                    method_getImplementation(method);
                method_setImplementation(method, (IMP)UCPCHookedInitWithConfig);
            }
        }

        // ─── Hook 2: 类方法 sessionWithConfiguration:delegate:delegateQueue: ───
        {
            SEL sel = @selector(sessionWithConfiguration:delegate:delegateQueue:);
            Method method = class_getClassMethod(sessionCls, sel);
            if (method) {
                gOriginalSessionFactoryIMP = (NSURLSession *(*)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *))
                    method_getImplementation(method);
                method_setImplementation(method, (IMP)UCPCHookedSessionFactory);
            }
        }

        NSString *log = @"[PointCastleHook] Delegate proxy hooks installed (init + factory method)";
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
    const uint8_t *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

@end