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
//  策略：Hook NSURLSession 的所有 dataTask 创建方法，加入诊断日志。
//  同时 hook completionHandler 和无 completionHandler 版本，
//  打印每个请求的 URL 来确认 Flutter 到底用了哪个 API。
//  
//  一旦确认 Flutter 的 session，就 swizzle 其 delegate 的
//  didReceiveData: / didCompleteWithError: 方法。
// ============================================================

// ─── Associated Object Keys ───
static char kTaskDataAccumKey;      // 关联到 task: 累积的响应数据

// ─── 保存原始 IMP 的全局变量 ───
static NSURLSessionDataTask *(*gOrigDataTaskWithReq)(id, SEL, NSURLRequest *) = NULL;
static NSURLSessionDataTask *(*gOrigDataTaskWithReqComp)(id, SEL, NSURLRequest *, void(^)(NSData *, NSURLResponse *, NSError *)) = NULL;
static NSURLSessionDataTask *(*gOrigDataTaskWithURL)(id, SEL, NSURL *) = NULL;
static NSURLSessionDataTask *(*gOrigDataTaskWithURLComp)(id, SEL, NSURL *, void(^)(NSData *, NSURLResponse *, NSError *)) = NULL;
static NSURLSessionDownloadTask *(*gOrigDownloadTaskWithReq)(id, SEL, NSURLRequest *) = NULL;
static NSURLSessionUploadTask *(*gOrigUploadTaskWithReq)(id, SEL, NSURLRequest *, NSData *) = NULL;

// ─── 已 swizzled 的 delegate 类集合 ───
static NSMutableSet<Class> *gSwizzledDelegateClasses = nil;
static NSLock *gSwizzleLock = nil;
static NSMutableDictionary<Class, NSMutableDictionary *> *gOriginalDelegateIMPs = nil;

// 诊断计数器
static NSUInteger gTotalDataTaskCalls = 0;
static NSUInteger gTotalResponseCount = 0;
static NSUInteger gMDTVMatchCount = 0;

// 诊断：记录最后 10 个 URL（限流用）
static NSMutableArray<NSString *> *gRecentURLs = nil;

// ============================================================
//  Hooked delegate 方法
// ============================================================

static void PC_HookedDidReceiveData(id self, SEL _cmd, NSURLSession *session,
                                     NSURLSessionDataTask *task, NSData *data) {
    if (data.length > 0) {
        NSMutableData *accum = objc_getAssociatedObject(task, &kTaskDataAccumKey);
        if (!accum) {
            accum = [NSMutableData data];
            objc_setAssociatedObject(task, &kTaskDataAccumKey, accum, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        if (accum.length < 512 * 1024) {
            NSUInteger remain = 512 * 1024 - accum.length;
            [accum appendData:[data subdataWithRange:NSMakeRange(0, MIN(remain, data.length))]];
        }
    }
    NSDictionary *imps = gOriginalDelegateIMPs[object_getClass(self)];
    IMP originalIMP = [imps[@"didReceiveData"] pointerValue];
    if (originalIMP) {
        ((void (*)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *))originalIMP)(self, _cmd, session, task, data);
    }
}

static void PC_HookedDidComplete(id self, SEL _cmd, NSURLSession *session,
                                  NSURLSessionTask *task, NSError *error) {
    NSMutableData *accum = objc_getAssociatedObject(task, &kTaskDataAccumKey);
    objc_setAssociatedObject(task, &kTaskDataAccumKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    if (!error && accum.length > 0) {
        gTotalResponseCount++;
        [UCPointCastleHookManager handleDecryptedResponse:accum];
    }

    NSDictionary *imps = gOriginalDelegateIMPs[object_getClass(self)];
    IMP originalIMP = [imps[@"didComplete"] pointerValue];
    if (originalIMP) {
        ((void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *))originalIMP)(self, _cmd, session, task, error);
    }
}

static void EnsureDelegateSwizzled(id delegate) {
    if (!delegate) return;
    Class cls = object_getClass(delegate);
    if (!cls) return;

    [gSwizzleLock lock];
    if ([gSwizzledDelegateClasses containsObject:cls]) {
        [gSwizzleLock unlock];
        return;
    }
    [gSwizzledDelegateClasses addObject:cls];
    [gSwizzleLock unlock];

    NSMutableDictionary *imps = [NSMutableDictionary dictionary];

    SEL dataSel = @selector(URLSession:dataTask:didReceiveData:);
    Method dataMethod = class_getInstanceMethod(cls, dataSel);
    if (dataMethod) {
        IMP original = method_getImplementation(dataMethod);
        imps[@"didReceiveData"] = [NSValue valueWithPointer:original];
        method_setImplementation(dataMethod, (IMP)PC_HookedDidReceiveData);
    }

    SEL completeSel = @selector(URLSession:task:didCompleteWithError:);
    Method completeMethod = class_getInstanceMethod(cls, completeSel);
    if (completeMethod) {
        IMP original = method_getImplementation(completeMethod);
        imps[@"didComplete"] = [NSValue valueWithPointer:original];
        method_setImplementation(completeMethod, (IMP)PC_HookedDidComplete);
    }

    gOriginalDelegateIMPs[(id)cls] = imps;

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] swizzled delegate class %@", NSStringFromClass(cls)];
    NSLog(@"%@", log);
    [[DatabaseManager sharedManager] insertLogText:log];
}

static void TrySwizzleSessionDelegate(NSURLSession *session) {
    if (!session) return;
    id delegate = session.delegate;
    if (delegate) {
        EnsureDelegateSwizzled(delegate);
    }
}

/// 诊断日志：记录 URL 和 delegate 类名
static void LogDataTask(NSString *methodName, NSURL *url, NSURLSession *session) {
    gTotalDataTaskCalls++;
    // 限流：每 10 个请求记一次，避免日志爆炸
    if (gTotalDataTaskCalls % 10 == 1) {
        NSString *host = url.host ?: @"(no host)";
        NSString *delegateClass = NSStringFromClass([session.delegate class]);
        if (!delegateClass) delegateClass = @"(nil delegate)";
        NSString *log = [NSString stringWithFormat:@"[PointCastleHook] #%lu %@ host=%@ delegate=%@",
                         (unsigned long)gTotalDataTaskCalls, methodName, host, delegateClass];
        NSLog(@"%@", log);
        [[DatabaseManager sharedManager] insertLogText:log];
    }
}

// ============================================================
//  Hook 实现 — 覆盖所有 dataTask/downloadTask/uploadTask 方法
// ============================================================

static NSURLSessionDataTask *PC_HookedDataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    LogDataTask(@"dataTaskWithReq:", request.URL, (NSURLSession *)self);
    TrySwizzleSessionDelegate((NSURLSession *)self);
    return gOrigDataTaskWithReq(self, _cmd, request);
}

static NSURLSessionDataTask *PC_HookedDataTaskWithRequestCompletion(id self, SEL _cmd, NSURLRequest *request,
    void(^handler)(NSData *, NSURLResponse *, NSError *)) {
    LogDataTask(@"dataTaskWithReq:completion:", request.URL, (NSURLSession *)self);
    // 如果带 completionHandler，我们也要包装它来拿到响应数据
    if (handler) {
        NSURL *origURL = request.URL;
        void(^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (!err && data.length > 0) {
                gTotalResponseCount++;
                [UCPointCastleHookManager handleDecryptedResponse:data];
            }
            handler(data, resp, err);
        };
        return gOrigDataTaskWithReqComp(self, _cmd, request, wrappedHandler);
    }
    return gOrigDataTaskWithReqComp(self, _cmd, request, handler);
}

static NSURLSessionDataTask *PC_HookedDataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    LogDataTask(@"dataTaskWithURL:", url, (NSURLSession *)self);
    TrySwizzleSessionDelegate((NSURLSession *)self);
    return gOrigDataTaskWithURL(self, _cmd, url);
}

static NSURLSessionDataTask *PC_HookedDataTaskWithURLCompletion(id self, SEL _cmd, NSURL *url,
    void(^handler)(NSData *, NSURLResponse *, NSError *)) {
    LogDataTask(@"dataTaskWithURL:completion:", url, (NSURLSession *)self);
    if (handler) {
        void(^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (!err && data.length > 0) {
                gTotalResponseCount++;
                [UCPointCastleHookManager handleDecryptedResponse:data];
            }
            handler(data, resp, err);
        };
        return gOrigDataTaskWithURLComp(self, _cmd, url, wrappedHandler);
    }
    return gOrigDataTaskWithURLComp(self, _cmd, url, handler);
}

static NSURLSessionDownloadTask *PC_HookedDownloadTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    LogDataTask(@"downloadTaskWithReq:", request.URL, (NSURLSession *)self);
    TrySwizzleSessionDelegate((NSURLSession *)self);
    return gOrigDownloadTaskWithReq(self, _cmd, request);
}

static NSURLSessionUploadTask *PC_HookedUploadTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, NSData *body) {
    LogDataTask(@"uploadTaskWithReq:", request.URL, (NSURLSession *)self);
    TrySwizzleSessionDelegate((NSURLSession *)self);
    return gOrigUploadTaskWithReq(self, _cmd, request, body);
}

// ============================================================
//  主管理器
// ============================================================

@interface UCPointCastleHookManager ()
@end

@implementation UCPointCastleHookManager

+ (void)initialize {
    if (self == [UCPointCastleHookManager class]) {
        gSwizzledDelegateClasses = [NSMutableSet set];
        gSwizzleLock = [[NSLock alloc] init];
        gOriginalDelegateIMPs = [NSMutableDictionary dictionary];
        gRecentURLs = [NSMutableArray array];
    }
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
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class sessionCls = [NSURLSession class];

        // Hook 所有 dataTask/downloadTask/uploadTask 创建方法
        struct HookEntry {
            SEL sel;
            BOOL isClassMethod;
            IMP *storage;
            IMP replacement;
        } entries[] = {
            { @selector(dataTaskWithRequest:), NO, (IMP *)&gOrigDataTaskWithReq, (IMP)PC_HookedDataTaskWithRequest },
            { @selector(dataTaskWithRequest:completionHandler:), NO, (IMP *)&gOrigDataTaskWithReqComp, (IMP)PC_HookedDataTaskWithRequestCompletion },
            { @selector(dataTaskWithURL:), NO, (IMP *)&gOrigDataTaskWithURL, (IMP)PC_HookedDataTaskWithURL },
            { @selector(dataTaskWithURL:completionHandler:), NO, (IMP *)&gOrigDataTaskWithURLComp, (IMP)PC_HookedDataTaskWithURLCompletion },
            { @selector(downloadTaskWithRequest:), NO, (IMP *)&gOrigDownloadTaskWithReq, (IMP)PC_HookedDownloadTaskWithRequest },
            { @selector(uploadTaskWithRequest:fromData:), NO, (IMP *)&gOrigUploadTaskWithReq, (IMP)PC_HookedUploadTaskWithRequest },
        };
        int count = sizeof(entries) / sizeof(entries[0]);

        for (int i = 0; i < count; i++) {
            Method method = entries[i].isClassMethod
                ? class_getClassMethod(sessionCls, entries[i].sel)
                : class_getInstanceMethod(sessionCls, entries[i].sel);
            if (method) {
                *entries[i].storage = method_getImplementation(method);
                method_setImplementation(method, entries[i].replacement);
            }
        }

        NSString *log = [NSString stringWithFormat:@"[PointCastleHook] installed %d dataTask hooks (all variants)", count];
        NSLog(@"%@", log);
        [[DatabaseManager sharedManager] insertLogText:log];
    });
}

#pragma mark - 响应检测入口

+ (void)handleDecryptedResponse:(NSData *)body {
    if (!body || body.length < 64) return;

    // 运行时检查开关状态（hooks 始终安装，但处理逻辑受开关控制）
    BOOL enabled = [[DatabaseManager sharedManager]
        getSwitch:@"pointycastle_hook_enabled"
        bundleID:[[NSBundle mainBundle] bundleIdentifier] ?: @"unknown"
        defaultValue:NO];
    if (!enabled) return;

    static const NSUInteger kParseWindowSize = 8 * 1024;
    NSUInteger parseLen = MIN(body.length, kParseWindowSize);
    NSData *tailData = [body subdataWithRange:NSMakeRange(body.length - parseLen, parseLen)];

    NSString *text = [[NSString alloc] initWithData:tailData encoding:NSUTF8StringEncoding];
    if (!text) return;

    NSRange dataRange = [text rangeOfString:@"\"data\"" options:NSBackwardsSearch];
    if (dataRange.location == NSNotFound) return;

    NSRange suffixRange = [text rangeOfString:@"\"suffix\"" options:NSBackwardsSearch];
    if (suffixRange.location == NSNotFound) return;

    NSUInteger suffixSearchStart = suffixRange.location;
    NSUInteger suffixSearchLen = MIN(64, text.length - suffixSearchStart);
    NSString *suffix = [self extractJSONStringValue:text key:@"suffix"
                                        searchRange:NSMakeRange(suffixSearchStart, suffixSearchLen)];

    NSUInteger dataSearchStart = dataRange.location;
    NSUInteger dataSearchLen = MIN(2048, text.length - dataSearchStart);
    NSString *b64Data = [self extractJSONStringValue:text key:@"data"
                                        searchRange:NSMakeRange(dataSearchStart, dataSearchLen)];

    if (!suffix || suffix.length != 6 || !b64Data || b64Data.length < 16) return;

    gMDTVMatchCount++;

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] #%lu captured MDTV suffix=%@ dataLen=%lu (total tasks: %lu, responses: %lu)",
                     (unsigned long)gMDTVMatchCount, suffix, (unsigned long)b64Data.length,
                     (unsigned long)gTotalDataTaskCalls, (unsigned long)gTotalResponseCount];
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

    NSData *suffixData = [suffix dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *iv2 = [NSMutableData dataWithLength:16];
    memset(iv2.mutableBytes, 0, 16);
    memcpy(iv2.mutableBytes, suffixData.bytes, MIN(suffixData.length, 16));
    [ivs addObject:iv2];

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