#import "UCFuncInterceptManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <substrate.h>
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>

static void recordIntercept(NSString *funcName, NSString *category, NSString *extra) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@ | %@", category, funcName, extra ?: @""];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"func_intercept"
                                                bundleID:bundleID
                                                    text:text];
}

// ──────────────────── 加密函数拦截 ────────────────────

static void *(*original_CC_SHA1)(const void *, CC_LONG, unsigned char *) = NULL;
static void *(*original_CC_SHA256)(const void *, CC_LONG, unsigned char *) = NULL;
static CCCryptorStatus (*original_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *) = NULL;

static unsigned char *hooked_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    recordIntercept(@"CC_SHA1", @"加密", [NSString stringWithFormat:@"len=%u", len]);
    return original_CC_SHA1(data, len, md);
}

static unsigned char *hooked_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    recordIntercept(@"CC_SHA256", @"加密", [NSString stringWithFormat:@"len=%u", len]);
    return original_CC_SHA256(data, len, md);
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
    return original_CCCrypt(op, alg, opt, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
}

// ──────────────────── 网络函数拦截 ────────────────────

static int (*original_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;

static int hooked_getaddrinfo(const char *hostname, const char *servname,
                               const struct addrinfo *hints, struct addrinfo **res) {
    if (hostname) {
        recordIntercept(@"getaddrinfo", @"网络", [NSString stringWithFormat:@"host=%s", hostname]);
    }
    return original_getaddrinfo(hostname, servname, hints, res);
}

// ──────────────────── 安装Hook ────────────────────

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
    // 优先按库路径查找，失败则全局搜索（兼容不同 iOS 版本）
    MSImageRef libCrypto = MSGetImageByName("/usr/lib/system/libcommonCrypto.dylib");

    void *symSHA1   = libCrypto ? MSFindSymbol(libCrypto, "_CC_SHA1")   : dlsym(RTLD_DEFAULT, "CC_SHA1");
    void *symSHA256 = libCrypto ? MSFindSymbol(libCrypto, "_CC_SHA256") : dlsym(RTLD_DEFAULT, "CC_SHA256");
    void *symCCCrypt = libCrypto ? MSFindSymbol(libCrypto, "_CCCrypt")   : dlsym(RTLD_DEFAULT, "CCCrypt");

    if (symSHA1)   MSHookFunction(symSHA1,   (void *)hooked_CC_SHA1,   (void **)&original_CC_SHA1);
    if (symSHA256) MSHookFunction(symSHA256, (void *)hooked_CC_SHA256, (void **)&original_CC_SHA256);
    if (symCCCrypt) MSHookFunction(symCCCrypt, (void *)hooked_CCCrypt, (void **)&original_CCCrypt);

    MSImageRef libSystem = MSGetImageByName("/usr/lib/libSystem.B.dylib");
    void *symGetAddr = libSystem ? MSFindSymbol(libSystem, "_getaddrinfo") : dlsym(RTLD_DEFAULT, "getaddrinfo");
    if (symGetAddr) MSHookFunction(symGetAddr, (void *)hooked_getaddrinfo, (void **)&original_getaddrinfo);

    NSUInteger hookCount = (symSHA1 ? 1 : 0) + (symSHA256 ? 1 : 0) + (symCCCrypt ? 1 : 0) + (symGetAddr ? 1 : 0);
    NSLog(@"[FuncIntercept] 拦截模块已安装 (%lu hooks)", (unsigned long)hookCount);
}

@end
