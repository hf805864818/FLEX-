#import "UCSocketCaptureManager.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/fishhook.h"
#import <sys/socket.h>
#import <sys/uio.h>
#import <CFNetwork/CFNetwork.h>

static NSString *(*orig_CFURLRequestCopyHTTPRequestBody)(CFURLRequestRef) = NULL;
static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_write)(int, const void *, size_t) = NULL;
static ssize_t (*orig_read)(int, void *, size_t) = NULL;

static NSString *CurrentBundleID(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
}

// 保存原始socket数据到数据库，不过滤
static void SaveRawSocketData(NSString *direction, int fd, NSData *data) {
    if (!data || data.length == 0) return;
    
    // 保存所有非空数据，二进制用base64 + 可读文本
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSString *b64 = [data base64EncodedStringWithOptions:0];
    
    NSString *entry = [NSString stringWithFormat:
                       @"[Socket %@ fd=%d len=%lu]\n"
                       @"UTF8: %@\n"
                       @"Base64: %@\n"
                       @"Hex: %@",
                       direction, fd, (unsigned long)data.length,
                       text ?: @"(binary)",
                       b64,
                       [self hexFromBytes:data.bytes length:MIN(data.length, 128)]];
    
    [[DatabaseManager sharedManager] insertDataIntoTable:@"url_responses"
                                                bundleID:CurrentBundleID()
                                                    text:entry];
}

+ (NSString *)hexFromBytes:(const void *)bytes length:(NSUInteger)length {
    if (!bytes || length == 0) return @"";
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    const unsigned char *ptr = (const unsigned char *)bytes;
    for (NSUInteger i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", ptr[i]];
    }
    return hex;
}

// ──────────────── CFNetwork Hook ────────────────
// Flutter dart:io 在 iOS 上用 CFNetwork 发送 HTTP 请求
// Hook CFReadStreamRead 来捕获发送的数据

static CFIndex (*orig_CFReadStreamRead)(CFReadStreamRef stream, UInt8 *buffer, CFIndex bufferLength) = NULL;

static CFIndex hooked_CFReadStreamRead(CFReadStreamRef stream, UInt8 *buffer, CFIndex bufferLength) {
    CFIndex ret = orig_CFReadStreamRead ? orig_CFReadStreamRead(stream, buffer, bufferLength)
                                         : CFReadStreamRead(stream, buffer, bufferLength);
    if (ret > 0) {
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)ret];
        // 只保存可能包含 ONE API 域名的数据
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (text && ([text containsString:@"em1oifd0"] || 
                     [text containsString:@"POST"] ||
                     [text containsString:@"sign"] ||
                     [text containsString:@"user-key"])) {
            NSString *entry = [NSString stringWithFormat:
                               @"[CFReadStream READ len=%ld]\n%@",
                               (long)ret, text];
            [[DatabaseManager sharedManager] insertDataIntoTable:@"url_responses"
                                                        bundleID:CurrentBundleID()
                                                            text:entry];
        }
    }
    return ret;
}

// ──────────────── Socket hooks (捕获所有数据，不过滤) ────────────────

static ssize_t hooked_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t ret = orig_send ? orig_send(fd, buf, len, flags) : send(fd, buf, len, flags);
    if (ret > 0) {
        [UCSocketCaptureManager saveRawData:@"SEND" fd:fd buf:buf len:(NSUInteger)ret];
    }
    return ret;
}

static ssize_t hooked_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t ret = orig_recv ? orig_recv(fd, buf, len, flags) : recv(fd, buf, len, flags);
    if (ret > 0) {
        [UCSocketCaptureManager saveRawData:@"RECV" fd:fd buf:buf len:(NSUInteger)ret];
    }
    return ret;
}

static ssize_t hooked_write(int fd, const void *buf, size_t len) {
    ssize_t ret = orig_write ? orig_write(fd, buf, len) : write(fd, buf, len);
    if (ret > 0) {
        [UCSocketCaptureManager saveRawData:@"WRITE" fd:fd buf:buf len:(NSUInteger)ret];
    }
    return ret;
}

static ssize_t hooked_read(int fd, void *buf, size_t len) {
    ssize_t ret = orig_read ? orig_read(fd, buf, len) : read(fd, buf, len);
    if (ret > 0) {
        [UCSocketCaptureManager saveRawData:@"READ" fd:fd buf:buf len:(NSUInteger)ret];
    }
    return ret;
}

static ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                              const struct sockaddr *destAddr, socklen_t addrLen) {
    ssize_t ret = orig_sendto ? orig_sendto(fd, buf, len, flags, destAddr, addrLen)
                               : sendto(fd, buf, len, flags, destAddr, addrLen);
    if (ret > 0) {
        [UCSocketCaptureManager saveRawData:@"SENDTO" fd:fd buf:buf len:(NSUInteger)ret];
    }
    return ret;
}

static ssize_t hooked_sendmsg(int fd, const struct msghdr *msg, int flags) {
    ssize_t ret = orig_sendmsg ? orig_sendmsg(fd, msg, flags)
                                : sendmsg(fd, msg, flags);
    if (ret > 0 && msg && msg->msg_iov && msg->msg_iovlen > 0) {
        NSMutableData *allData = [NSMutableData data];
        for (int i = 0; i < msg->msg_iovlen; i++) {
            [allData appendBytes:msg->msg_iov[i].iov_base
                          length:msg->msg_iov[i].iov_len];
        }
        [UCSocketCaptureManager saveRawData:@"SENDMSG" fd:fd buf:allData.bytes len:allData.length];
    }
    return ret;
}

@implementation UCSocketCaptureManager

+ (instancetype)sharedManager {
    static UCSocketCaptureManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCSocketCaptureManager alloc] init];
    });
    return instance;
}

// 保存原始数据，不过滤任何内容
+ (void)saveRawData:(NSString *)direction fd:(int)fd buf:(const void *)buf len:(NSUInteger)len {
    if (!buf || len == 0) return;
    
    NSData *data = [NSData dataWithBytes:buf length:len];
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSString *b64 = [data base64EncodedStringWithOptions:0];
    
    // 获取前64字节的hex
    NSMutableString *hex = [NSMutableString stringWithCapacity:128];
    const unsigned char *ptr = (const unsigned char *)buf;
    NSUInteger hexLen = MIN(len, (NSUInteger)64);
    for (NSUInteger i = 0; i < hexLen; i++) {
        [hex appendFormat:@"%02x", ptr[i]];
    }
    if (len > 64) [hex appendString:@"..."];
    
    NSString *entry = [NSString stringWithFormat:
                       @"[SOCKET %@ fd=%d len=%lu]\n"
                       @"UTF8 Preview: %@\n"
                       @"Base64: %@\n"
                       @"Hex(%lu): %@",
                       direction, fd, (unsigned long)len,
                       text ? [text substringToIndex:MIN(text.length, 200)] : @"(binary)",
                       b64,
                       (unsigned long)hexLen, hex];
    
    [[DatabaseManager sharedManager] insertDataIntoTable:@"url_responses"
                                                bundleID:CurrentBundleID()
                                                    text:entry];
}

- (void)installHooks {
    struct rebinding rebindings[] = {
        {"send",     hooked_send,    (void **)&orig_send},
        {"sendto",   hooked_sendto,  (void **)&orig_sendto},
        {"sendmsg",  hooked_sendmsg, (void **)&orig_sendmsg},
        {"recv",     hooked_recv,    (void **)&orig_recv},
        {"write",    hooked_write,   (void **)&orig_write},
        {"read",     hooked_read,    (void **)&orig_read},
    };

    int result = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(struct rebinding));
    
    NSUInteger count = 0;
    if (orig_send) { count++; NSLog(@"[SocketCapture] send hooked"); }
    if (orig_sendto) { count++; NSLog(@"[SocketCapture] sendto hooked"); }
    if (orig_sendmsg) { count++; NSLog(@"[SocketCapture] sendmsg hooked"); }
    if (orig_recv) { count++; NSLog(@"[SocketCapture] recv hooked"); }
    if (orig_write) { count++; NSLog(@"[SocketCapture] write hooked"); }
    if (orig_read) { count++; NSLog(@"[SocketCapture] read hooked"); }
    
    NSLog(@"[SocketCapture] Socket hook 已安装 (%lu hooks 成功, rebind=%d)", (unsigned long)count, result);
    
    if (count == 0) {
        NSLog(@"[SocketCapture] ⚠️ fishhook 没有找到任何符号！Flutter 可能静态链接了 socket 函数");
        // 兜底：直接尝试通过 dlsym 查找
        orig_send = dlsym(RTLD_DEFAULT, "send");
        orig_recv = dlsym(RTLD_DEFAULT, "recv");
        orig_write = dlsym(RTLD_DEFAULT, "write");
        orig_read = dlsym(RTLD_DEFAULT, "read");
        NSLog(@"[SocketCapture] dlsym 找到 send=%p, recv=%p, write=%p, read=%p", 
              orig_send, orig_recv, orig_write, orig_read);
    }
}

@end
