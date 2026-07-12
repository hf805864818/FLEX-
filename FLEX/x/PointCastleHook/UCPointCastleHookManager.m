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
//  策略：hook NSURLSession 的 dataTaskWithRequest:/dataTaskWithURL:
//  （无 completionHandler 版本，Flutter dart:io 用的就是这两个）。
//
//  每次 task 创建时，通过 session.delegate 找到原始 delegate，
//  然后 swizzle 其 didReceiveData: / didCompleteWithError: 方法。
//
//  这样无论 Flutter 的 session 是何时创建的，我们都能拦截到。
// ============================================================

// ─── Associated Object Keys ───
static char kTaskDataAccumKey;      // 关联到 task: 累积的响应数据

// ─── 保存原始 IMP 的全局变量 ───
static NSURLSessionDataTask *(*gOriginalDataTaskWithRequest)(id, SEL, NSURLRequest *) = NULL;
static NSURLSessionDataTask *(*gOriginalDataTaskWithURL)(id, SEL, NSURL *) = NULL;

// ─── 已 swizzled 的 delegate 类集合（线程安全用锁） ───
static NSMutableSet<Class> *gSwizzledDelegateClasses = nil;
static NSLock *gSwizzleLock = nil;

// ─── 原始 delegate IMP 映射：Class -> { "didReceiveData" -> NSValue(IMP), "didComplete" -> NSValue(IMP) } ───
static NSMutableDictionary<Class, NSMutableDictionary *> *gOriginalDelegateIMPs = nil;

// 诊断计数器
static NSUInteger gTotalResponseCount = 0;
static NSUInteger gMDTVMatchCount = 0;

// ============================================================
//  Hooked delegate 方法
// ============================================================

/// 替换后的 didReceiveData: — 累积响应数据
static void PC_HookedDidReceiveData(id self, SEL _cmd, NSURLSession *session,
                                     NSURLSessionDataTask *task, NSData *data) {
    // 累积数据到 task 的关联对象
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

    // 调用原始 IMP
    NSDictionary *imps = gOriginalDelegateIMPs[object_getClass(self)];
    IMP originalIMP = [imps[@"didReceiveData"] pointerValue];
    if (originalIMP) {
        ((void (*)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *))originalIMP)(self, _cmd, session, task, data);
    }
}

/// 替换后的 didCompleteWithError: — 触发密钥检测
static void PC_HookedDidComplete(id self, SEL _cmd, NSURLSession *session,
                                  NSURLSessionTask *task, NSError *error) {
    // 获取累积的数据
    NSMutableData *accum = objc_getAssociatedObject(task, &kTaskDataAccumKey);
    objc_setAssociatedObject(task, &kTaskDataAccumKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    if (!error && accum.length > 0) {
        gTotalResponseCount++;
        [UCPointCastleHookManager handleDecryptedResponse:accum];
    }

    // 调用原始 IMP
    NSDictionary *imps = gOriginalDelegateIMPs[object_getClass(self)];
    IMP originalIMP = [imps[@"didComplete"] pointerValue];
    if (originalIMP) {
        ((void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *))originalIMP)(self, _cmd, session, task, error);
    }
}

/// 如果 delegate 的类还未被 swizzle，则执行 swizzle
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

    // 保存原始 IMP
    NSMutableDictionary *imps = [NSMutableDictionary dictionary];

    // Swizzle didReceiveData:
    SEL dataSel = @selector(URLSession:dataTask:didReceiveData:);
    Method dataMethod = class_getInstanceMethod(cls, dataSel);
    if (dataMethod) {
        IMP original = method_getImplementation(dataMethod);
        imps[@"didReceiveData"] = [NSValue valueWithPointer:original];
        method_setImplementation(dataMethod, (IMP)PC_HookedDidReceiveData);
    }

    // Swizzle didCompleteWithError:
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

/// 从 session 获取 delegate 并 swizzle 其方法
static void TrySwizzleSessionDelegate(NSURLSession *session) {
    if (!session) return;
    // NSURLSession.delegate 是 public readonly 属性
    id delegate = session.delegate;
    if (delegate) {
        EnsureDelegateSwizzled(delegate);
    }
}

// ============================================================
//  Hook 实现
// ============================================================

/// Hook: -[NSURLSession dataTaskWithRequest:]（无 completionHandler）
/// Flutter dart:io 在 iOS 上使用此方法创建 HTTP 请求
static NSURLSessionDataTask *PC_HookedDataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    TrySwizzleSessionDelegate((NSURLSession *)self);
    return gOriginalDataTaskWithRequest(self, _cmd, request);
}

/// Hook: -[NSURLSession dataTaskWithURL:]（无 completionHandler）
/// Flutter 某些场景可能使用此方法
static NSURLSessionDataTask *PC_HookedDataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    TrySwizzleSessionDelegate((NSURLSession *)self);
    return gOriginalDataTaskWithURL(self, _cmd, url);
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

        // ─── Hook 1: dataTaskWithRequest: (无 completionHandler) ───
        {
            SEL sel = @selector(dataTaskWithRequest:);
            Method method = class_getInstanceMethod(sessionCls, sel);
            if (method) {
                gOriginalDataTaskWithRequest = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *))
                    method_getImplementation(method);
                method_setImplementation(method, (IMP)PC_HookedDataTaskWithRequest);
            }
        }

        // ─── Hook 2: dataTaskWithURL: (无 completionHandler) ───
        {
            SEL sel = @selector(dataTaskWithURL:);
            Method method = class_getInstanceMethod(sessionCls, sel);
            if (method) {
                gOriginalDataTaskWithURL = (NSURLSessionDataTask *(*)(id, SEL, NSURL *))
                    method_getImplementation(method);
                method_setImplementation(method, (IMP)PC_HookedDataTaskWithURL);
            }
        }

        NSString *log = @"[PointCastleHook] dataTask hooks installed (intercept delegate methods on task creation)";
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

    gMDTVMatchCount++;

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] #%lu captured MDTV suffix=%@ dataLen=%lu (total responses: %lu)",
                     (unsigned long)gMDTVMatchCount, suffix, (unsigned long)b64Data.length, (unsigned long)gTotalResponseCount];
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