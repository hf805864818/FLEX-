#import "UCFuncInterceptManager.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/fishhook.h"
#import <CommonCrypto/CommonCrypto.h>

static void recordIntercept(NSString *funcName, NSString *category, NSString *extra) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@ | %@", category, funcName, extra ?: @""];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"func_intercept"
                                                bundleID:bundleID
                                                    text:text];
}

// ──────────────────── 加密函数拦截 ────────────────────

static unsigned char *(*original_CC_SHA1)(const void *, CC_LONG, unsigned char *) = NULL;
static unsigned char *(*original_CC_SHA256)(const void *, CC_LONG, unsigned char *) = NULL;
static CCCryptorStatus (*original_CCCrypt)(CCOperation, CCAlgorithm, CCOptions,
    const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *) = NULL;

static unsigned char *hooked_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    recordIntercept(@"CC_SHA1", @"加密", [NSString stringWithFormat:@"len=%u", len]);
    return original_CC_SHA1 ? original_CC_SHA1(data, len, md) : NULL;
}

static unsigned char *hooked_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    recordIntercept(@"CC_SHA256", @"加密", [NSString stringWithFormat:@"len=%u", len]);
    return original_CC_SHA256 ? original_CC_SHA256(data, len, md) : NULL;
}

static CCCryptorStatus hooked_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt,
                                       const void *key, size_t keyLen, const void *iv,
                                       const void *dataIn, size_t dataInLen,
                                       void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    NSString *opStr = (op == kCCEncrypt) ? @"加密" : @"解密";
    NSString *algStr = @"?";
    if (alg == kCCAlgorithmAES128) algStr = @"AES";
    else if (alg == kCCAlgorithmDES) algStr = @"DES";
    else if (alg == kCCAlgorithm3DES) algStr = @"3DES";
    else if (alg == kCCAlgorithmRC4) algStr = @"RC4";
    recordIntercept(@"CCCrypt", @"加密", [NSString stringWithFormat:@"%@ %@ len=%zu", opStr, algStr, dataInLen]);
    return original_CCCrypt ? original_CCCrypt(op, alg, opt, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved) : kCCUnimplemented;
}

// ──────────────────── 网络函数拦截 ────────────────────

static int (*original_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;

static int hooked_getaddrinfo(const char *hostname, const char *servname,
                               const struct addrinfo *hints, struct addrinfo **res) {
    if (hostname) {
        recordIntercept(@"getaddrinfo", @"网络", [NSString stringWithFormat:@"host=%s", hostname]);
    }
    return original_getaddrinfo ? original_getaddrinfo(hostname, servname, hints, res) : EAI_FAIL;
}

// ──────────────────── 安装Hook（使用 fishhook 而非 Substrate，兼容 iOS 17）────────────────────

@implementation UCFuncInterceptManager

+ (instancetype)sharedManager {
    static UCFuncInterceptManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCFuncInterceptManager alloc] init];
    });
    return instance;
}

- (void)installHooks {
    struct rebinding rebindings[] = {
        {"CC_SHA1",   hooked_CC_SHA1,   (void *)&original_CC_SHA1},
        {"CC_SHA256", hooked_CC_SHA256, (void *)&original_CC_SHA256},
        {"CCCrypt",   hooked_CCCrypt,   (void *)&original_CCCrypt},
        {"getaddrinfo", hooked_getaddrinfo, (void *)&original_getaddrinfo},
    };

    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(struct rebinding));

    // 统计实际成功 hook 的数量
    NSUInteger count = 0;
    if (original_CC_SHA1) count++;
    if (original_CC_SHA256) count++;
    if (original_CCCrypt) count++;
    if (original_getaddrinfo) count++;
    NSLog(@"[FuncIntercept] 拦截模块已安装 (%lu hooks via fishhook)", (unsigned long)count);
}

@end
