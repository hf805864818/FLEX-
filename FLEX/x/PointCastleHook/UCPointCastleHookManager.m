#import "UCPointCastleHookManager.h"
#import "UCDartMemoryScanner.h"
#import "UCAESKeyValidator.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/fishhook.h"
#import <sys/socket.h>
#import <sys/uio.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <pthread.h>

// 目标域名关键字
static NSString * const kMDTVHostKeyword = @"nzp1ve";

// 响应体缓存阈值
static const NSUInteger kMaxResponseBuffer = 2 * 1024 * 1024;  // 2MB

// 同一个 fd 的去抖间隔（秒）
static const NSTimeInterval kScanDebounceInterval = 1.5;

// 扫描锁：防止并发拖垮性能
static pthread_mutex_t gScanLock = PTHREAD_MUTEX_INITIALIZER;
static NSTimeInterval gLastScanTime = 0;

// 原函数指针
static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_recvmsg)(int, struct msghdr *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;

// 记录目标 fd
static NSMutableSet<NSNumber *> *gTargetFds = nil;
static dispatch_queue_t gHookQueue = nil;

// 每个 fd 的响应体缓冲
static NSMutableDictionary<NSNumber *, NSMutableData *> *gResponseBuffers = nil;
// 每个目标 fd 的最后活动时间（用于清理过期 fd，防止连接关闭后 buffer 残留）
static NSMutableDictionary<NSNumber *, NSDate *> *gFdLastActivity = nil;

@interface UCPointCastleHookManager ()
@end

@implementation UCPointCastleHookManager

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gTargetFds = [NSMutableSet set];
        gResponseBuffers = [NSMutableDictionary dictionary];
        gFdLastActivity = [NSMutableDictionary dictionary];
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
    dispatch_async(gHookQueue, ^{
        struct rebinding rebindings[] = {
            {"connect",  hooked_connect,  (void **)&orig_connect},
            {"recvmsg",  hooked_recvmsg,  (void **)&orig_recvmsg},
            {"recv",     hooked_recv,     (void **)&orig_recv},
        };

        int count = sizeof(rebindings) / sizeof(rebindings[0]);
        int result = rebind_symbols(rebindings, count);

        NSUInteger success = 0;
        if (orig_connect) success++;
        if (orig_recvmsg) success++;
        if (orig_recv) success++;

        NSString *log = [NSString stringWithFormat:
                         @"[PointCastleHook] installed: %lu/%d (rebind=%d)",
                         (unsigned long)success, count, result];
        NSLog(@"%@", log);
        [[DatabaseManager sharedManager] insertLogText:log];

        // 兜底：dlsym 获取原始函数
        if (!orig_connect) orig_connect = dlsym(RTLD_DEFAULT, "connect");
        if (!orig_recvmsg) orig_recvmsg = dlsym(RTLD_DEFAULT, "recvmsg");
        if (!orig_recv)    orig_recv    = dlsym(RTLD_DEFAULT, "recv");
    });
}

#pragma mark - Hook 函数

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = orig_connect ? orig_connect(sockfd, addr, addrlen) : connect(sockfd, addr, addrlen);

    if (ret == 0 && addr && addrlen >= sizeof(struct sockaddr)) {
        NSString *targetInfo = [UCPointCastleHookManager endpointDescription:addr];
        if (targetInfo && [targetInfo rangeOfString:kMDTVHostKeyword options:NSCaseInsensitiveSearch].location != NSNotFound) {
            dispatch_async(gHookQueue, ^{
                [gTargetFds addObject:@(sockfd)];
            });
            NSString *log = [NSString stringWithFormat:@"[PointCastleHook] target connect fd=%d %@", sockfd, targetInfo];
            NSLog(@"%@", log);
            [[DatabaseManager sharedManager] insertLogText:log];
        }
    }

    return ret;
}

static ssize_t hooked_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    ssize_t ret = orig_recvmsg ? orig_recvmsg(sockfd, msg, flags) : recvmsg(sockfd, msg, flags);

    if (ret > 0) {
        NSData *chunk = nil;
        if (msg && msg->msg_iov && msg->msg_iovlen > 0) {
            NSMutableData *all = [NSMutableData data];
            ssize_t remaining = ret;
            for (int i = 0; i < msg->msg_iovlen && remaining > 0; i++) {
                size_t take = MIN((size_t)remaining, msg->msg_iov[i].iov_len);
                if (take > 0) {
                    [all appendBytes:msg->msg_iov[i].iov_base length:take];
                    remaining -= take;
                }
            }
            chunk = all;
        }
        [UCPointCastleHookManager handleReceivedData:chunk ?: [NSData data] onFd:sockfd];
    }

    return ret;
}

static ssize_t hooked_recv(int sockfd, void *buf, size_t len, int flags) {
    ssize_t ret = orig_recv ? orig_recv(sockfd, buf, len, flags) : recv(sockfd, buf, len, flags);

    if (ret > 0 && buf) {
        NSData *chunk = [NSData dataWithBytes:buf length:(NSUInteger)ret];
        [UCPointCastleHookManager handleReceivedData:chunk onFd:sockfd];
    }

    return ret;
}

#pragma mark - 数据处理

+ (void)handleReceivedData:(NSData *)data onFd:(int)fd {
    if (!data || data.length == 0) return;

    [self cleanupStaleEntries];

    __block BOOL isTarget = NO;
    dispatch_sync(gHookQueue, ^{
        isTarget = [gTargetFds containsObject:@(fd)];
    });
    if (!isTarget) return;

    // 简单协议识别：MDTV 响应是 HTTP/1.1 或 HTTP/2 封装后的 JSON
    // 先尝试把当前 chunk 当文本看看是否含关键字
    NSString *preview = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (preview && ([preview rangeOfString:@"\"data\""].location != NSNotFound ||
                    [preview rangeOfString:@"\"suffix\""].location != NSNotFound ||
                    [preview rangeOfString:kMDTVHostKeyword].location != NSNotFound)) {
        // 可能已经开始进入 body
    }

    // 累积缓冲
    dispatch_async(gHookQueue, ^{
        NSNumber *fdKey = @(fd);
        gFdLastActivity[fdKey] = [NSDate date];

        NSMutableData *buffer = gResponseBuffers[fdKey];
        if (!buffer) {
            buffer = [NSMutableData data];
            gResponseBuffers[fdKey] = buffer;
        }
        [buffer appendData:data];

        if (buffer.length > kMaxResponseBuffer) {
            buffer.length = kMaxResponseBuffer; // 截断防 OOM
        }

        // 累积到一定量或遇到结束特征后触发解析
        [self tryParseResponseBuffer:buffer fd:fd];
    });
}

+ (void)tryParseResponseBuffer:(NSMutableData *)buffer fd:(int)fd {
    if (buffer.length < 64) return;

    // 记录活动时间，用于过期清理
    NSNumber *fdKey = @(fd);
    gFdLastActivity[fdKey] = [NSDate date];

    // 从 buffer 尾部开始查找 JSON 对象 {"suffix":"...","data":"..."}
    NSString *text = [[NSString alloc] initWithData:buffer encoding:NSUTF8StringEncoding];
    if (!text) return;

    NSRange dataRange = [text rangeOfString:@"\"data\"" options:NSBackwardsSearch];
    if (dataRange.location == NSNotFound) return;

    NSRange suffixRange = [text rangeOfString:@"\"suffix\"" options:NSBackwardsSearch];
    if (suffixRange.location == NSNotFound) return;

    // 提取 suffix（6 位 hex）
    NSString *suffix = [self extractJSONStringValue:text key:@"suffix" searchRange:NSMakeRange(suffixRange.location, MIN(64, text.length - suffixRange.location))];
    NSString *b64Data = [self extractJSONStringValue:text key:@"data" searchRange:NSMakeRange(dataRange.location, MIN(2048, text.length - dataRange.location))];

    if (!suffix || suffix.length != 6 || !b64Data || b64Data.length < 16) return;

    // 清除缓冲避免重复触发
    [buffer setLength:0];

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] captured response suffix=%@ dataLen=%lu fd=%d", suffix, (unsigned long)b64Data.length, fd];
    NSLog(@"%@", log);
    [[DatabaseManager sharedManager] insertLogText:log];

    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:b64Data options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!cipherData || cipherData.length == 0) return;

    // IV：suffix 是 6 位 hex，pointycastle 常见做法是在 IV 前补零到 16 字节，
    // 也可能直接把 suffix 当 hex 转成 3 字节后再补齐，这里同时尝试几种。
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

    // 2. suffix 直接 UTF-8 编码后补零到 16 字节（某些 app 简单实现）
    NSData *suffixData = [suffix dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *iv2 = [NSMutableData dataWithLength:16];
    memset(iv2.mutableBytes, 0, 16);
    memcpy(iv2.mutableBytes, suffixData.bytes, MIN(suffixData.length, 16));
    [ivs addObject:iv2];

    // 3. 全零 IV（ECB 候选实际上会忽略 IV，但保留统一接口）
    [ivs addObject:[NSMutableData dataWithLength:16]];

    return ivs;
}

#pragma mark - 扫描 + 验证

+ (void)triggerScanAndValidateWithCiphertext:(NSData *)ciphertext ivCandidates:(NSArray<NSData *> *)ivCandidates {
    pthread_mutex_lock(&gScanLock);
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (now - gLastScanTime < kScanDebounceInterval) {
        pthread_mutex_unlock(&gScanLock);
        return;
    }
    gLastScanTime = now;
    pthread_mutex_unlock(&gScanLock);

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] start scan for ciphertext length=%lu", (unsigned long)ciphertext.length];
    NSLog(@"%@", log);
    [[DatabaseManager sharedManager] insertLogText:log];

    // 候选数量降低 + 验证放到后台线程，避免阻塞主线程或被 Jetsam
    [[UCDartMemoryScanner sharedScanner] scanForAESKeyCandidates:100 completion:^(NSArray<NSData *> *candidates) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [self validateCandidates:candidates ciphertext:ciphertext ivCandidates:ivCandidates];
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

#pragma mark - 过期 fd / buffer 清理

+ (void)cleanupStaleEntries {
    dispatch_async(gHookQueue, ^{
        NSDate *now = [NSDate date];
        NSArray<NSNumber *> *keys = [gFdLastActivity allKeys];
        for (NSNumber *fdKey in keys) {
            NSDate *last = gFdLastActivity[fdKey];
            if (!last || [now timeIntervalSinceDate:last] > 30.0) {
                [gTargetFds removeObject:fdKey];
                [gResponseBuffers removeObjectForKey:fdKey];
                [gFdLastActivity removeObjectForKey:fdKey];
            }
        }
    });
}

#pragma mark - 手动触发（调试用）

- (void)triggerValidationWithResponseBody:(NSData *)responseBody {
    if (!responseBody || responseBody.length == 0) return;
    [UCPointCastleHookManager handleReceivedData:responseBody onFd:-1];
}

#pragma mark - 工具方法

+ (nullable NSString *)endpointDescription:(const struct sockaddr *)addr {
    if (!addr) return nil;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        return [NSString stringWithFormat:@"%s:%d", ip, ntohs(sin->sin_port)];
    }
    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        return [NSString stringWithFormat:@"[%s]:%d", ip, ntohs(sin6->sin6_port)];
    }
    return nil;
}

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
