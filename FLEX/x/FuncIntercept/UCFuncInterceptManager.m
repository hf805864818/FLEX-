#import "UCFuncInterceptManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <substrate.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

static void recordIntercept(NSString *funcName, NSString *category, NSString *extra) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@ | %@", category, funcName, extra ?: @""];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"func_intercept"
                                                bundleID:bundleID
                                                longText:text];
}

// ──────────────────── 加密函数拦截 ────────────────────

static void *(*original_CC_SHA1)(const void *, CC_LONG, unsigned char *) = NULL;
static void *(*original_CC_SHA256)(const void *, CC_LONG, unsigned char *) = NULL;
static void *(*original_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *) = NULL;

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
    MSImageRef libSystem = MSGetImageByName("/usr/lib/system/libcommonCrypto.dylib");
    if (libSystem) {
        MSHookFunction(MSFindSymbol(libSystem, "_CC_SHA1"),
                       (void *)hooked_CC_SHA1,
                       (void **)&original_CC_SHA1);
        MSHookFunction(MSFindSymbol(libSystem, "_CC_SHA256"),
                       (void *)hooked_CC_SHA256,
                       (void **)&original_CC_SHA256);
        MSHookFunction(MSFindSymbol(libSystem, "_CCCrypt"),
                       (void *)hooked_CCCrypt,
                       (void **)&original_CCCrypt);
    }

    MSImageRef libC = MSGetImageByName("/usr/lib/libSystem.B.dylib");
    if (libC) {
        MSHookFunction(MSFindSymbol(libC, "_getaddrinfo"),
                       (void *)hooked_getaddrinfo,
                       (void **)&original_getaddrinfo);
    }

    NSLog(@"[FuncIntercept] 拦截模块已安装 (4 hooks)");
}

@end
