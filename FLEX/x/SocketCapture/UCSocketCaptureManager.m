#import "UCSocketCaptureManager.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/fishhook.h"
#import <sys/socket.h>
#import <sys/uio.h>

static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_write)(int, const void *, size_t) = NULL;
static ssize_t (*orig_read)(int, void *, size_t) = NULL;

static NSString *CurrentBundleID(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
}

static void SaveSocketData(NSString *direction, int fd, NSData *data) {
    if (!data || data.length < 4) return;
    
    const uint8_t *bytes = data.bytes;
    BOOL isHTTP = (data.length >= 4 && bytes[0]=='P' && bytes[1]=='O' && bytes[2]=='S' && bytes[3]=='T');
    BOOL isJSON = (bytes[0] == '{');
    BOOL hasSign = (memmem(bytes, data.length, "sign", 4) != NULL);
    BOOL hasApiDomain = (memmem(bytes, data.length, "em1oifd0", 8) != NULL);
    
    if (!isHTTP && !isJSON && !hasSign && !hasApiDomain) return;
    
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text || text.length == 0) return;
    
    [[DatabaseManager sharedManager] insertDataIntoTable:@"url_responses"
                                                bundleID:CurrentBundleID()
                                                    text:[NSString stringWithFormat:
                                                          @"[Socket %@ fd=%d]\n%@",
                                                          direction, fd, text]];
}

static ssize_t hooked_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t ret = orig_send ? orig_send(fd, buf, len, flags) : send(fd, buf, len, flags);
    if (ret > 0) {
        SaveSocketData(@"SEND", fd, [NSData dataWithBytes:buf length:(NSUInteger)ret]);
    }
    return ret;
}

static ssize_t hooked_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t ret = orig_recv ? orig_recv(fd, buf, len, flags) : recv(fd, buf, len, flags);
    if (ret > 0) {
        SaveSocketData(@"RECV", fd, [NSData dataWithBytes:buf length:(NSUInteger)ret]);
    }
    return ret;
}

static ssize_t hooked_write(int fd, const void *buf, size_t len) {
    ssize_t ret = orig_write ? orig_write(fd, buf, len) : write(fd, buf, len);
    if (ret > 0) {
        SaveSocketData(@"WRITE", fd, [NSData dataWithBytes:buf length:(NSUInteger)ret]);
    }
    return ret;
}

static ssize_t hooked_read(int fd, void *buf, size_t len) {
    ssize_t ret = orig_read ? orig_read(fd, buf, len) : read(fd, buf, len);
    if (ret > 0) {
        SaveSocketData(@"READ", fd, [NSData dataWithBytes:buf length:(NSUInteger)ret]);
    }
    return ret;
}

static ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                              const struct sockaddr *destAddr, socklen_t addrLen) {
    ssize_t ret = orig_sendto ? orig_sendto(fd, buf, len, flags, destAddr, addrLen)
                               : sendto(fd, buf, len, flags, destAddr, addrLen);
    if (ret > 0) {
        SaveSocketData(@"SENDTO", fd, [NSData dataWithBytes:buf length:(NSUInteger)ret]);
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
        SaveSocketData(@"SENDMSG", fd, allData);
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

    int result = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(struct rebinding));
    
    NSUInteger count = 0;
    if (orig_send) count++;
    if (orig_recv) count++;
    if (orig_write) count++;
    if (orig_read) count++;
    if (orig_sendto) count++;
    if (orig_sendmsg) count++;
    
    NSLog(@"[SocketCapture] Socket 层 Hook 已安装 (%lu hooks, rebind=%d)", (unsigned long)count, result);
}

@end
