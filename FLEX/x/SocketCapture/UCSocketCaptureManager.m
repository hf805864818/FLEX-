#import "UCSocketCaptureManager.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/fishhook.h"
#import <sys/socket.h>
#import <sys/uio.h>
#import <dlfcn.h>

static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_write)(int, const void *, size_t) = NULL;
static ssize_t (*orig_read)(int, void *, size_t) = NULL;

static NSString *CurrentBundleID(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
}

// 纯C辅助函数: hex编码
static NSString *HexFromBuf(const void *buf, size_t len) {
    if (!buf || len == 0) return @"";
    NSMutableString *hex = [NSMutableString stringWithCapacity:len * 2];
    const unsigned char *ptr = (const unsigned char *)buf;
    size_t showLen = len > 128 ? 128 : len;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02x", ptr[i]];
    }
    if (len > 128) [hex appendString:@"..."];
    return hex;
}

// 纯C辅助函数: 保存数据到数据库
static void SaveRawData(const char *direction, int fd, const void *buf, size_t len) {
    if (!buf || len == 0) return;
    
    NSData *data = [NSData dataWithBytes:buf length:len];
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSString *b64 = [data base64EncodedStringWithOptions:0];
    NSString *hex = HexFromBuf(buf, len);
    
    NSString *preview = text ? [text substringToIndex:MIN(text.length, 500)] : @"(binary)";
    
    NSString *entry = [NSString stringWithFormat:
                       @"[SOCKET %s fd=%d len=%zu]\n"
                       @"UTF8: %@\n"
                       @"Base64: %@\n"
                       @"Hex: %@",
                       direction, fd, len, preview, b64, hex];
    
    [[DatabaseManager sharedManager] insertDataIntoTable:@"url_responses"
                                                bundleID:CurrentBundleID()
                                                    text:entry];
}

// ─── hooked send ───
static ssize_t hooked_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t ret = orig_send ? orig_send(fd, buf, len, flags) : send(fd, buf, len, flags);
    if (ret > 0) {
        SaveRawData("SEND", fd, buf, (size_t)ret);
    }
    return ret;
}

// ─── hooked recv ───
static ssize_t hooked_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t ret = orig_recv ? orig_recv(fd, buf, len, flags) : recv(fd, buf, len, flags);
    if (ret > 0) {
        SaveRawData("RECV", fd, buf, (size_t)ret);
    }
    return ret;
}

// ─── hooked write ───
static ssize_t hooked_write(int fd, const void *buf, size_t len) {
    ssize_t ret = orig_write ? orig_write(fd, buf, len) : write(fd, buf, len);
    if (ret > 0) {
        SaveRawData("WRITE", fd, buf, (size_t)ret);
    }
    return ret;
}

// ─── hooked read ───
static ssize_t hooked_read(int fd, void *buf, size_t len) {
    ssize_t ret = orig_read ? orig_read(fd, buf, len) : read(fd, buf, len);
    if (ret > 0) {
        SaveRawData("READ", fd, buf, (size_t)ret);
    }
    return ret;
}

// ─── hooked sendto ───
static ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                              const struct sockaddr *destAddr, socklen_t addrLen) {
    ssize_t ret = orig_sendto ? orig_sendto(fd, buf, len, flags, destAddr, addrLen)
                               : sendto(fd, buf, len, flags, destAddr, addrLen);
    if (ret > 0) {
        SaveRawData("SENDTO", fd, buf, (size_t)ret);
    }
    return ret;
}

// ─── hooked sendmsg ───
static ssize_t hooked_sendmsg(int fd, const struct msghdr *msg, int flags) {
    ssize_t ret = orig_sendmsg ? orig_sendmsg(fd, msg, flags)
                                : sendmsg(fd, msg, flags);
    if (ret > 0 && msg && msg->msg_iov && msg->msg_iovlen > 0) {
        // 合并所有 iov
        size_t total = 0;
        for (int i = 0; i < msg->msg_iovlen; i++) {
            total += msg->msg_iov[i].iov_len;
        }
        NSMutableData *allData = [NSMutableData dataWithLength:total];
        size_t offset = 0;
        for (int i = 0; i < msg->msg_iovlen; i++) {
            memcpy((uint8_t *)allData.mutableBytes + offset,
                   msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
            offset += msg->msg_iov[i].iov_len;
        }
        SaveRawData("SENDMSG", fd, allData.bytes, allData.length);
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

- (void)installHooks {
    struct rebinding rebindings[] = {
        {"send",     hooked_send,    (void **)&orig_send},
        {"sendto",   hooked_sendto,  (void **)&orig_sendto},
        {"sendmsg",  hooked_sendmsg, (void **)&orig_sendmsg},
        {"recv",     hooked_recv,    (void **)&orig_recv},
        {"write",    hooked_write,   (void **)&orig_write},
        {"read",     hooked_read,    (void **)&orig_read},
    };

    int n = sizeof(rebindings) / sizeof(rebindings[0]);
    int result = rebind_symbols(rebindings, n);
    
    NSUInteger count = 0;
    if (orig_send) count++;
    if (orig_sendto) count++;
    if (orig_sendmsg) count++;
    if (orig_recv) count++;
    if (orig_write) count++;
    if (orig_read) count++;
    
    NSLog(@"[SocketCapture] Socket hook 已安装: %lu/%d 成功 (rebind=%d)", 
          (unsigned long)count, n, result);
    
    // 兜底尝试 dlsym
    if (count == 0) {
        NSLog(@"[SocketCapture] fishhook 未找到符号，尝试 dlsym 兜底...");
        orig_send = dlsym(RTLD_DEFAULT, "send");
        orig_recv = dlsym(RTLD_DEFAULT, "recv");
        orig_write = dlsym(RTLD_DEFAULT, "write");
        orig_read = dlsym(RTLD_DEFAULT, "read");
        orig_sendto = dlsym(RTLD_DEFAULT, "sendto");
        NSLog(@"[SocketCapture] dlsym 找到: send=%p recv=%p write=%p read=%p sendto=%p",
              orig_send, orig_recv, orig_write, orig_read, orig_sendto);
    }
}

@end
