#import "UCMemoryScanManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>

static void recordScan(NSString *matchType, NSString *value) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@", matchType, value];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"memory_scan"
                                                bundleID:bundleID
                                                    text:text];
}

@interface UCMemoryScanManager ()
@property (nonatomic, assign) BOOL isScanning;
@property (nonatomic, strong) NSTimer *scanTimer;
@property (nonatomic, assign) NSUInteger scanCount;
@end

@implementation UCMemoryScanManager

+ (instancetype)sharedManager {
    static UCMemoryScanManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCMemoryScanManager alloc] init];
    });
    return instance;
}

- (void)dealloc {
    [self.scanTimer invalidate];
}

- (void)startScan {
    if (self.isScanning) return;
    self.isScanning = YES;
    self.scanCount = 0;

    // 每10秒自动扫描一次，共6次
    self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:10.0
                                                      target:self
                                                    selector:@selector(performMemoryScan)
                                                    userInfo:nil
                                                     repeats:YES];
    [self performMemoryScan]; // 立即执行第一次

    NSLog(@"[MemoryScan] 内存扫描已启动");
}

- (void)stopScan {
    self.isScanning = NO;
    [self.scanTimer invalidate];
    self.scanTimer = nil;
    NSLog(@"[MemoryScan] 内存扫描已停止");
}

- (void)performMemoryScan {
    if (!self.isScanning) return;

    self.scanCount++;
    NSLog(@"[MemoryScan] 第 %lu 次扫描...", (unsigned long)self.scanCount);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self scanRegisteredClasses];
        [self scanLoadedLibraries];   // ★ 新增：扫描动态库
        [self scanProcessMemory];     // ★ 新增：扫描进程内存
    });
    [self scanUserDefaults];
    [self scanInfoPlist];

    if (self.scanCount >= 6) {
        [self stopScan];
    }
}

- (void)scanRegisteredClasses {
    unsigned int classCount = 0;
    Class *classList = objc_copyClassList(&classCount);

    for (unsigned int i = 0; i < classCount && i < 500; i++) {
        Class cls = classList[i];
        @try {
            NSString *className = NSStringFromClass(cls);

            if ([className hasPrefix:@"_"] ||
                [className hasPrefix:@"NS"] ||
                [className hasPrefix:@"UI"] ||
                [className hasPrefix:@"CA"] ||
                [className hasPrefix:@"CF"] ||
                [className hasPrefix:@"WK"] ||
                [className hasPrefix:@"OS"] ||
                [className hasPrefix:@"AV"] ||
                [className hasPrefix:@"PK"] ||
                [className hasPrefix:@"CG"] ||
                [className hasPrefix:@"CI"] ||
                [className hasPrefix:@"CT"] ||
                [className hasPrefix:@"FB"] ||
                [className hasPrefix:@"AS"] ||
                [className hasPrefix:@"FLEX"] ||
                [className hasPrefix:@"Capture"] ||
                [className hasPrefix:@"UC"] ||
                [className hasPrefix:@"Database"] ||
                [className hasPrefix:@"CDZip"] ||
                [className hasPrefix:@"FH"] ||
                [className hasPrefix:@"RTB"] ||
                [className hasPrefix:@"IZX"]) {
                continue;
            }

            BOOL hasCrypto = [self checkCryptoMethodsOnClass:cls]
                          || [self checkCryptoMethodsOnClass:object_getClass(cls)];

            if (hasCrypto) {
                recordScan(@"加密常量", [NSString stringWithFormat:@"类 %@ 包含加密方法", className]);
            }
        } @catch (NSException *exception) {
        }
    }
    free(classList);
}

- (BOOL)checkCryptoMethodsOnClass:(Class)cls {
    if (!cls) return NO;
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    if (!methods) return NO;

    BOOL found = NO;
    for (unsigned int j = 0; j < methodCount && j < 100; j++) {
        NSString *methodName = NSStringFromSelector(method_getName(methods[j]));
        NSString *low = methodName.lowercaseString;
        if ([low containsString:@"encrypt"] || [low containsString:@"decrypt"] ||
            [low containsString:@"aes"] || [low containsString:@"des"] ||
            [low containsString:@"crypto"] || [low containsString:@"key"] ||
            [low containsString:@"sign"] || [low containsString:@"hash"] ||
            [low containsString:@"token"]) {
            found = YES;
            break;
        }
    }
    free(methods);
    return found;
}

- (void)scanUserDefaults {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults dictionaryRepresentation];

    for (NSString *key in dict) {
        NSString *lowerKey = key.lowercaseString;
        if ([lowerKey containsString:@"token"] ||
            [lowerKey containsString:@"key"] ||
            [lowerKey containsString:@"secret"] ||
            [lowerKey containsString:@"password"] ||
            [lowerKey containsString:@"auth"] ||
            [lowerKey containsString:@"credential"] ||
            [lowerKey containsString:@"encrypt"] ||
            [lowerKey containsString:@"crypto"]) {
            recordScan(@"密钥格式", [NSString stringWithFormat:@"NSUserDefaults[%@] = ***", key]);
        }
    }
}

- (void)scanInfoPlist {
    NSDictionary *infoPlist = [[NSBundle mainBundle] infoDictionary];
    for (NSString *key in infoPlist) {
        NSString *lowerKey = key.lowercaseString;
        if ([lowerKey containsString:@"api"] ||
            [lowerKey containsString:@"key"] ||
            [lowerKey containsString:@"secret"] ||
            [lowerKey containsString:@"token"] ||
            [lowerKey containsString:@"url"]) {
            id val = infoPlist[key];
            // 对敏感值仅输出类型和长度，不暴露真实内容
            NSString *desc;
            if ([val isKindOfClass:[NSString class]]) {
                desc = [NSString stringWithFormat:@"(String, %lu chars)", (unsigned long)[(NSString *)val length]];
            } else if ([val isKindOfClass:[NSNumber class]]) {
                desc = @"(Number)";
            } else if ([val isKindOfClass:[NSArray class]]) {
                desc = [NSString stringWithFormat:@"(Array, %lu items)", (unsigned long)[(NSArray *)val count]];
            } else if ([val isKindOfClass:[NSDictionary class]]) {
                desc = [NSString stringWithFormat:@"(Dict, %lu keys)", (unsigned long)[(NSDictionary *)val count]];
            } else if ([val isKindOfClass:[NSData class]]) {
                desc = [NSString stringWithFormat:@"(Data, %lu bytes)", (unsigned long)[(NSData *)val length]];
            } else {
                desc = [NSString stringWithFormat:@"(%@)", NSStringFromClass([val class])];
            }
            recordScan(@"密钥格式", [NSString stringWithFormat:@"Info.plist[%@] = %@", key, desc]);
        }
    }
}

// ★ 新增：扫描已加载动态库的 __cstring 段，搜索硬编码的 AES Key（安全版本）
- (void)scanLoadedLibraries {
    @autoreleasepool {
    @try {
        uint32_t imageCount = _dyld_image_count();
        for (uint32_t i = 0; i < imageCount; i++) {
            @autoreleasepool {
                const char *name = _dyld_get_image_name(i);
                if (!name) continue;
                NSString *libName = [NSString stringWithUTF8String:name];
                if (![libName containsString:@"libapp"] &&
                    ![libName containsString:@"libflutter"] &&
                    ![libName containsString:@".app/"]) continue;
                
                unsigned long csize = 0;
                uint8_t *cdata = getsectiondata(
                    (const struct mach_header_64 *)_dyld_get_image_header(i),
                    "__TEXT", "__cstring", &csize);
                if (!cdata || csize == 0) {
                    cdata = getsectiondata(
                        (const struct mach_header_64 *)_dyld_get_image_header(i),
                        "__TEXT", "__const", &csize);
                }
                if (!cdata || csize == 0 || csize > 50*1024*1024) continue;
                
                NSData *cdataObj = [NSData dataWithBytes:cdata length:csize];
                if (!cdataObj) continue;
                
                // 搜索已知密钥
                NSArray *keys = @[@"563e8eeef42931cc858dc0d1080f4f6f",@"368480924a6c78e2e8681551a7cf4c21"];
                for (NSString *k in keys) {
                    NSData *kd = [k dataUsingEncoding:NSUTF8StringEncoding];
                    if (kd && cdataObj.length >= kd.length &&
                        [cdataObj rangeOfData:kd options:0 range:NSMakeRange(0,cdataObj.length)].location != NSNotFound) {
                        recordScan(@"已知密钥", [NSString stringWithFormat:@"[%@] 发现密钥: %@", [libName lastPathComponent], k]);
                    }
                }
                
                // 用bytes直接扫描32位hex，避免NSString转换崩溃
                NSUInteger scanLen = MIN((NSUInteger)csize, (NSUInteger)500000);
                const uint8_t *bytes = cdata;
                char hexBuf[33] = {0};
                int pos = 0;
                
                for (NSUInteger j = 0; j < scanLen; j++) {
                    char c = (char)bytes[j];
                    BOOL isH = (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
                    if (isH && pos < 32) { hexBuf[pos++] = c; }
                    else { pos = 0; memset(hexBuf,0,33); }
                    
                    if (pos == 32) {
                        BOOL hasL=NO, hasD=NO;
                        for (int k=0;k<32;k++) {
                            if (hexBuf[k]>='0'&&hexBuf[k]<='9') hasD=YES;
                            else hasL=YES;
                        }
                        if (hasL&&hasD) {
                            recordScan(@"AES密钥候选", [NSString stringWithFormat:@"[%@] 32hex: %.32s", [libName lastPathComponent], hexBuf]);
                        }
                        memmove(hexBuf, hexBuf+1, 31);
                        pos = 31;
                    }
                }
            }
        }
    } @catch (NSException *e) {
        recordScan(@"库扫描异常", [NSString stringWithFormat:@"异常: %@", e.reason]);
    }
    }
}

// ★ 新增：扫描 __data 段搜索密钥（安全版本）
- (void)scanProcessMemory {
    @autoreleasepool {
    @try {
        uint32_t imageCount = _dyld_image_count();
        for (uint32_t i = 0; i < imageCount; i++) {
            @autoreleasepool {
                const char *name = _dyld_get_image_name(i);
                if (!name) continue;
                NSString *libName = [NSString stringWithUTF8String:name];
                if (![libName containsString:@"libapp"] &&
                    ![libName containsString:@"libflutter"] &&
                    ![libName containsString:@".app/"]) continue;
                
                unsigned long dsize = 0;
                uint8_t *ddata = getsectiondata(
                    (const struct mach_header_64 *)_dyld_get_image_header(i),
                    "__DATA", "__data", &dsize);
                if (!ddata || dsize == 0 || dsize > 50*1024*1024) continue;
                
                NSUInteger scanLen = MIN((NSUInteger)dsize, (NSUInteger)500000);
                const uint8_t *bytes = ddata;
                char buf[33] = {0};
                int pos = 0;
                
                for (NSUInteger j = 0; j < scanLen; j++) {
                    char c = (char)bytes[j];
                    BOOL isH = (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
                    if (isH && pos < 32) { buf[pos++] = c; }
                    else {
                        if (pos >= 24 && pos <= 32) {
                            BOOL hasL=NO, hasD=NO;
                            for (int k=0;k<pos;k++) {
                                if (buf[k]>='0'&&buf[k]<='9') hasD=YES;
                                else hasL=YES;
                            }
                            if (hasL&&hasD) {
                                buf[pos]='\0';
                                recordScan(@"进程密钥", [NSString stringWithFormat:@"[%@] %dhex: %s", [libName lastPathComponent], pos, buf]);
                            }
                        }
                        pos = 0; memset(buf,0,33);
                    }
                }
            }
        }
    } @catch (NSException *e) {
        recordScan(@"进程扫描异常", [NSString stringWithFormat:@"异常: %@", e.reason]);
    }
    }
}

// ★ 新增扫描到 performMemoryScan 中

@end
