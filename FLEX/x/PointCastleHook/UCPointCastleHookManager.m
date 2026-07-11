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

// 响应体缓存阈值（MDTV JSON 响应通常只有几 KB）
static const NSUInteger kMaxResponseBuffer = 64 * 1024;  // 64KB

// 同一个 fd 的去抖间隔（秒）
static const NSTimeInterval kScanDebounceInterval = 5.0;

// 扫描锁：防止并发拖垮性能
static pthread_mutex_t gScanLock = PTHREAD_MUTEX_INITIALIZER;
static NSTimeInterval gLastScanTime = 0;
static BOOL gIsScanning = NO;

// 原函数指针
static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_recvmsg)(int, struct msghdr *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;

// 每个 fd 的响应体缓冲（只保留最近活跃的 fd，防止泄漏）
static NSMutableDictionary<NSNumber *, NSMutableData *> *gResponseBuffers = nil;
static NSMutableDictionary<NSNumber *, NSDate *> *gFdLastActivity = nil;
static dispatch_queue_t gHookQueue = nil;
static BOOL gHooksInstalled = NO;

@interface UCPointCastleHookManager ()
@end

@implementation UCPointCastleHookManager

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
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
    if (gHooksInstalled) {
        NSLog(@"[PointCastleHook] hooks already installed, skipping");
        return;
    }

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

    gHooksInstalled = YES;
}

#pragma mark - Hook 函数

// connect 不再用于 fd 过滤，只保留日志记录
static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = orig_connect ? orig_connect(sockfd, addr, addrlen) : connect(sockfd, addr, addrlen);

    if (ret == 0 && addr && addrlen >= sizeof(struct sockaddr)) {
        // 仅记录日志，不再用于 fd 过滤
        // （endpointDescription 返回 IP 地址，无法匹配域名关键字）
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

    // 定期清理过期 fd 的 buffer
    [self cleanupStaleEntries];

    // 快速预筛：丢弃明显是二进制流的数据（视频/图片/加密流）
    // 阈值降低到 50% 以避免误判短 chunk
    if (![self isLikelyTextData:data]) return;

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
            buffer.length = kMaxResponseBuffer;
        }

        [self tryParseResponseBuffer:buffer fd:fd];
    });
}

+ (void)tryParseResponseBuffer:(NSMutableData *)buffer fd:(int)fd {
    if (buffer.length < 64) return;

    NSNumber *fdKey = @(fd);
    gFdLastActivity[fdKey] = [NSDate date];

    // 只解析尾部 8KB，避免为大响应分配巨大 NSString
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

    NSString *log = [NSString stringWithFormat:@"[PointCastleHook] captured response suffix=%@ dataLen=%lu fd=%d",
                     suffix, (unsigned long)b64Data.length, fd];
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

#pragma mark - 过期 fd / buffer 清理

+ (void)cleanupStaleEntries {
    // 限制同时活跃的 fd 数量，防止 buffer 无限增长
    dispatch_async(gHookQueue, ^{
        NSDate *now = [NSDate date];
        NSArray<NSNumber *> *keys = [gFdLastActivity allKeys];

        // 超过 30 秒不活动或总数超过 50 个 fd 时清理
        BOOL needCleanup = (keys.count > 50);
        for (NSNumber *fdKey in keys) {
            NSDate *last = gFdLastActivity[fdKey];
            if (needCleanup || !last || [now timeIntervalSinceDate:last] > 30.0) {
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

+ (BOOL)isLikelyTextData:(NSData *)data {
    if (!data || data.length == 0) return NO;

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger sampleLen = MIN(data.length, (NSUInteger)512);
    NSUInteger printable = 0;

    for (NSUInteger i = 0; i < sampleLen; i++) {
        uint8_t c = bytes[i];
        if ((c >= 0x20 && c <= 0x7E) || c == '\r' || c == '\n' || c == '\t') {
            printable++;
        }
    }

    // 降低到 50%：HTTP/2 响应开头可能包含少量二进制帧头
    return (printable * 100 / sampleLen) >= 50;
}

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