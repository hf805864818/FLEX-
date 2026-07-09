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

// ★ 新增：扫描已加载动态库的 __cstring 段，搜索硬编码的 AES Key
- (void)scanLoadedLibraries {
    uint32_t imageCount = _dyld_image_count();
    
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *libName = [NSString stringWithUTF8String:name];
        
        // 只扫描目标应用相关库
        if (![libName containsString:@"libapp"] &&
            ![libName containsString:@"libflutter"] &&
            ![libName containsString:@".app/"]) {
            continue;
        }
        
        recordScan(@"库扫描", [NSString stringWithFormat:@"扫描动态库: %@", libName]);
        
        // 获取 __cstring 段 - 使用 getsectiondata（公开API，无链接问题）
        unsigned long csize = 0;
        uint8_t *cdata = getsectiondata(
            (const struct mach_header_64 *)_dyld_get_image_header(i),
            "__TEXT", "__cstring", &csize
        );
        
        if (!cdata || csize == 0) {
            // 也试试 __const 段
            cdata = getsectiondata(
                (const struct mach_header_64 *)_dyld_get_image_header(i),
                "__TEXT", "__const", &csize
            );
        }
        
        if (!cdata || csize == 0) continue;
        
        char *cstrings = (char *)cdata;
        unsigned long size = csize;
        
        recordScan(@"库扫描", [NSString stringWithFormat:@"%@ __cstring 段大小: %lu bytes",
                               [libName lastPathComponent], size]);
        
        // 搜索 32 位 hex 字符串（AES-128 Key 格式）
        NSString *allStrings = [NSString stringWithUTF8String:cstrings];
        
        // 搜索已知的ONE平台密钥
        NSArray *knownKeys = @[
            @"563e8eeef42931cc858dc0d1080f4f6f",
            @"368480924a6c78e2e8681551a7cf4c21",
            @"48b067ec-6cfd-3491-84f5-023eb1e7d562",
            @"em1oifd0",
            @"5pkwjhp",
        ];
        
        for (NSString *key in knownKeys) {
            if ([allStrings containsString:key]) {
                recordScan(@"已知密钥", [NSString stringWithFormat:
                    @"[lib: %@] 发现密钥: %@",
                    [libName lastPathComponent], key]);
            }
        }
        
        // 搜索 32 位 hex 格式的 AES Key 候选
        if (allStrings.length > 1000) {
            NSUInteger searchLen = MIN(allStrings.length, (NSUInteger)5000000);
            NSString *searchStr = [allStrings substringToIndex:searchLen];
            
            // 手动扫描 32 位 hex
            NSCharacterSet *hexSet = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"];
            NSMutableString *currentHex = [NSMutableString string];
            
            for (NSUInteger j = 0; j < searchStr.length; j++) {
                unichar c = [searchStr characterAtIndex:j];
                if ([hexSet characterIsMember:c]) {
                    [currentHex appendFormat:@"%C", c];
                    if (currentHex.length == 32) {
                        // 检查是否包含字母和数字（混合的才是真密钥）
                        BOOL hasLetter = NO, hasDigit = NO;
                        for (NSUInteger k = 0; k < 32; k++) {
                            unichar kc = [currentHex characterAtIndex:k];
                            if (kc >= '0' && kc <= '9') hasDigit = YES;
                            else hasLetter = YES;
                        }
                        if (hasLetter && hasDigit) {
                            recordScan(@"AES密钥候选", [NSString stringWithFormat:
                                @"[lib: %@] 32位hex: %@",
                                [libName lastPathComponent], currentHex]);
                        }
                        [currentHex deleteCharactersInRange:NSMakeRange(0, 1)];
                    }
                } else {
                    [currentHex setString:@""];
                }
            }
            
            // 搜索 16 位 hex 格式（可能是部分密钥）
            for (NSUInteger j = 0; j < searchStr.length; j++) {
                unichar c = [searchStr characterAtIndex:j];
                if ([hexSet characterIsMember:c]) {
                    [currentHex appendFormat:@"%C", c];
                    if (currentHex.length == 16) {
                        BOOL hasLetter = NO, hasDigit = NO;
                        for (NSUInteger k = 0; k < 16; k++) {
                            unichar kc = [currentHex characterAtIndex:k];
                            if (kc >= '0' && kc <= '9') hasDigit = YES;
                            else hasLetter = YES;
                        }
                        if (hasLetter && hasDigit) {
                            recordScan(@"密钥候选", [NSString stringWithFormat:
                                @"[lib: %@] 16位hex: %@",
                                [libName lastPathComponent], currentHex]);
                        }
                        [currentHex deleteCharactersInRange:NSMakeRange(0, 1)];
                    }
                } else {
                    [currentHex setString:@""];
                }
            }
        }
    }
}

// ★ 新增：扫描整个进程内存中的 AES Key 特征
- (void)scanProcessMemory {
    // 使用 vm_region 遍历进程内存
    vm_address_t address = 0;
    vm_size_t size = 0;
    natural_t depth = 1;
    
    while (YES) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        
        kern_return_t kr = vm_region_recurse_64(mach_task_self(),
                                                &address, &size, &depth,
                                                (vm_region_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        
        // 只扫描可读且不是空的区域
        if (info.protection & VM_PROT_READ && size > 0) {
            // 搜索常见密钥模式
            const uint8_t *bytes = (const uint8_t *)address;
            
            // 搜索 "563e8eee" 开头的模式
            const uint8_t pattern[] = {0x35, 0x36, 0x33, 0x65, 0x38, 0x65, 0x65, 0x65};
            for (vm_size_t offset = 0; offset < size - 8; offset++) {
                if (memcmp(bytes + offset, pattern, 8) == 0) {
                    // 读取完整的 hex 字符串（最多 32 位）
                    char hexBuf[33] = {0};
                    vm_size_t hexLen = MIN((vm_size_t)32, size - offset);
                    memcpy(hexBuf, bytes + offset, hexLen);
                    recordScan(@"进程内存密钥", [NSString stringWithUTF8String:hexBuf]);
                }
            }
        }
        
        address += size;
        if (address == 0) break;
    }
    
    recordScan(@"进程扫描", @"进程内存扫描完成");
}

// ★ 新增扫描到 performMemoryScan 中

@end
