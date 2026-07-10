#import "UCMemoryScanManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <malloc/malloc.h>
#import <CommonCrypto/CommonDigest.h>

// ─── 最大扫描大小限制（防止 OOM）───
static const NSUInteger kMaxSectionScanSize = 10 * 1024 * 1024;  // 每个 Mach-O 段最大扫 10MB
static const NSUInteger kMaxHeapScanBytes   = 50 * 1024 * 1024;  // 堆内存最多扫 50MB
static const NSUInteger kMaxResultsPerScan  = 200;               // 单次扫描最多记录 200 条

// ─── 扫描结果计数器（防止刷爆数据库）───
static NSUInteger gResultsCount = 0;

static BOOL ShouldRecord(void) {
    if (gResultsCount >= kMaxResultsPerScan) return NO;
    gResultsCount++;
    return YES;
}

static void recordScan(NSString *matchType, NSString *value) {
    if (!ShouldRecord()) return;
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@", matchType, value];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"memory_scan"
                                                bundleID:bundleID
                                                    text:text];
}

#pragma mark - Shannon 熵计算

static double CalculateShannonEntropy(const uint8_t *data, NSUInteger length) {
    if (!data || length == 0) return 0.0;

    // 频率统计
    uint32_t freq[256] = {0};
    for (NSUInteger i = 0; i < length; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)length;
        entropy -= p * log2(p);
    }
    return entropy;
}

#pragma mark - Hex 字符检测

static BOOL IsValidHexChar(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static BOOL HexStringHasMixedCase(const char *hex, int len) {
    BOOL hasDigit = NO, hasLetter = NO;
    for (int i = 0; i < len; i++) {
        if (hex[i] >= '0' && hex[i] <= '9') hasDigit = YES;
        else hasLetter = YES;
    }
    return hasDigit && hasLetter;
}

#pragma mark - Base64 字符检测

static BOOL IsValidBase64Char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

#pragma mark - 高熵数据块扫描

typedef struct {
    const uint8_t *start;
    NSUInteger length;
    double entropy;
} HighEntropyBlock;

static void ScanForHighEntropyBlocks(const uint8_t *data, NSUInteger dataLength,
                                      const char *sourceLabel, double entropyThreshold,
                                      NSUInteger minBlockSize, NSUInteger maxBlockSize) {
    if (!data || dataLength < minBlockSize) return;

    NSUInteger pos = 0;
    while (pos <= dataLength - minBlockSize) {
        // 找到一个窗口大小的高熵块
        NSUInteger windowSize = minBlockSize;
        if (windowSize > dataLength - pos) break;

        double entropy = CalculateShannonEntropy(data + pos, windowSize);

        if (entropy >= entropyThreshold) {
            // 尝试扩展到最大块大小，找到连续高熵区域
            NSUInteger endPos = pos + windowSize;
            while (endPos + 1 <= dataLength && (endPos - pos + 1) <= maxBlockSize) {
                double extEntropy = CalculateShannonEntropy(data + pos, endPos - pos + 1);
                if (extEntropy >= entropyThreshold - 0.1) {
                    endPos++;
                } else {
                    break;
                }
            }

            NSUInteger blockLen = endPos - pos;
            if (blockLen >= minBlockSize) {
                // 生成 hex 预览
                NSUInteger previewLen = MIN(blockLen, (NSUInteger)64);
                NSMutableString *hexPreview = [NSMutableString stringWithCapacity:previewLen * 2];
                for (NSUInteger i = 0; i < previewLen; i++) {
                    [hexPreview appendFormat:@"%02x", data[pos + i]];
                }

                double finalEntropy = CalculateShannonEntropy(data + pos, blockLen);
                recordScan(@"高熵数据",
                    [NSString stringWithFormat:@"[%s] 偏移 0x%lx, %lu 字节, 熵=%.2f\nHex: %@%@",
                        sourceLabel,
                        (unsigned long)pos, (unsigned long)blockLen, finalEntropy,
                        hexPreview,
                        blockLen > 64 ? @"\n...(已截断)" : @""]);

                pos = endPos; // 跳过已扫描的区域
                continue;
            }
        }
        pos++;
    }
}

#pragma mark - AES/DES 密钥长度高熵块扫描

// 搜索恰好 16/24/32 字节的高熵数据块（AES-128/192/256 密钥长度）
static void ScanForKeyLengthPatterns(const uint8_t *data, NSUInteger dataLength,
                                       const char *sourceLabel) {
    if (!data || dataLength < 16) return;

    // 密钥长度候选
    const NSUInteger keyLengths[] = {16, 24, 32};
    const int numLengths = 3;

    for (int kl = 0; kl < numLengths; kl++) {
        NSUInteger keyLen = keyLengths[kl];
        const char *keyTypeName = (keyLen == 16) ? "AES-128" :
                                   (keyLen == 24) ? "AES-192/3DES" : "AES-256";

        for (NSUInteger i = 0; i <= dataLength - keyLen; i++) {
            double entropy = CalculateShannonEntropy(data + i, keyLen);
            if (entropy >= 7.5) {  // 极高熵，可能是密钥
                // 额外检查：确保不是全 0xFF 或全 0x00
                BOOL allSame = YES;
                uint8_t first = data[i];
                for (NSUInteger j = 1; j < keyLen; j++) {
                    if (data[i + j] != first) { allSame = NO; break; }
                }
                if (allSame) continue;

                NSMutableString *hex = [NSMutableString stringWithCapacity:keyLen * 3];
                for (NSUInteger j = 0; j < keyLen; j++) {
                    if (j > 0) [hex appendString:@" "];
                    [hex appendFormat:@"%02x", data[i + j]];
                }

                recordScan(@"密钥候选",
                    [NSString stringWithFormat:@"[%s] %s 密钥候选 @ 0x%lx (熵=%.2f)\nHex: %@",
                        sourceLabel, keyTypeName, (unsigned long)i, entropy, hex]);

                // 找到一个就跳过一段，避免连续报告
                i += keyLen;
            }
        }
    }
}

#pragma mark - 连续 hex 字符串扫描（原有逻辑增强版）

static void ScanForHexStringSequences(const uint8_t *data, NSUInteger dataLength,
                                        const char *sourceLabel, int targetLength) {
    if (!data || dataLength < (NSUInteger)targetLength) return;

    NSUInteger scanLen = MIN(dataLength, (NSUInteger)500000);
    char hexBuf[65] = {0}; // 支持到 64 字符
    int pos = 0;

    for (NSUInteger j = 0; j < scanLen; j++) {
        char c = (char)data[j];
        BOOL isH = IsValidHexChar(c);

        if (isH && pos < 64) {
            hexBuf[pos++] = c;
        } else {
            // 遇到非 hex 字符，检查当前缓冲区
            if (pos >= targetLength) {
                hexBuf[pos] = '\0';
                if (HexStringHasMixedCase(hexBuf, pos)) {
                    recordScan(@"Hex密钥",
                        [NSString stringWithFormat:@"[%s] %d字符hex: %.32s%@",
                            sourceLabel, pos, hexBuf,
                            pos > 32 ? @"..." : @""]);
                }
            }
            pos = 0;
            memset(hexBuf, 0, sizeof(hexBuf));
        }

        if (pos == 64) {
            hexBuf[pos] = '\0';
            if (HexStringHasMixedCase(hexBuf, pos)) {
                recordScan(@"Hex密钥",
                    [NSString stringWithFormat:@"[%s] 64字符hex: %.32s...",
                        sourceLabel, hexBuf]);
            }
            memmove(hexBuf, hexBuf + 1, 63);
            pos = 63;
        }
    }

    // 处理末尾
    if (pos >= targetLength) {
        hexBuf[pos] = '\0';
        if (HexStringHasMixedCase(hexBuf, pos)) {
            recordScan(@"Hex密钥",
                [NSString stringWithFormat:@"[%s] %d字符hex: %.32s%@",
                    sourceLabel, pos, hexBuf,
                    pos > 32 ? @"..." : @""]);
        }
    }
}

#pragma mark - Base64 编码密钥扫描

static void ScanForBase64Keys(const uint8_t *data, NSUInteger dataLength,
                                const char *sourceLabel) {
    if (!data || dataLength < 16) return;

    NSUInteger scanLen = MIN(dataLength, (NSUInteger)500000);
    NSUInteger pos = 0;

    while (pos < scanLen) {
        // 跳过非 Base64 字符
        while (pos < scanLen && !IsValidBase64Char(data[pos])) pos++;
        if (pos >= scanLen) break;

        NSUInteger start = pos;
        while (pos < scanLen && IsValidBase64Char(data[pos])) pos++;

        NSUInteger len = pos - start;
        // Base64 编码的 AES-128 key = 24 字符 (16 bytes * 4/3 ≈ 24)
        // AES-256 key = 44 字符 (32 bytes * 4/3 ≈ 44)
        if ((len >= 22 && len <= 26) || (len >= 42 && len <= 46) || len == 88) {
            char *buf = (char *)malloc(len + 1);
            if (!buf) continue;
            memcpy(buf, data + start, len);
            buf[len] = '\0';

            NSString *b64str = [[NSString alloc] initWithBytesNoCopy:buf
                                                              length:len
                                                            encoding:NSUTF8StringEncoding
                                                      freeWhenDone:YES];
            if (b64str) {
                // 尝试 Base64 解码
                NSData *decoded = [[NSData alloc] initWithBase64EncodedString:b64str
                                                                  options:NSDataBase64DecodingIgnoreUnknownCharacters];
                if (decoded) {
                    // 检查解码后数据的熵
                    double entropy = CalculateShannonEntropy(decoded.bytes, decoded.length);
                    if (entropy >= 7.0 && decoded.length >= 16) {
                        NSMutableString *hexPreview = [NSMutableString string];
                        NSUInteger previewLen = MIN(decoded.length, (NSUInteger)32);
                        for (NSUInteger i = 0; i < previewLen; i++) {
                            [hexPreview appendFormat:@"%02x", decoded.bytes[i]];
                        }

                        recordScan(@"Base64密钥",
                            [NSString stringWithFormat:@"[%s] Base64 → %lu 字节 (熵=%.2f)\n原文: %@\nHex: %@%@",
                                sourceLabel, (unsigned long)decoded.length, entropy,
                                [b64str substringToIndex:MIN(b64str.length, (NSUInteger)48)],
                                hexPreview,
                                decoded.length > 32 ? @"..." : @""]);
                    }
                }
            }
        }
    }
}

#pragma mark - 已知密钥扫描（保留原逻辑）

static void ScanForKnownKeys(const uint8_t *data, NSUInteger dataLength,
                               const char *sourceLabel) {
    if (!data || dataLength == 0) return;

    // 已知的常见密钥模式
    NSArray *knownPatterns = @[
        @"563e8eeef42931cc858dc0d1080f4f6f",
        @"368480924a6c78e2e8681551a7cf4c21",
    ];

    NSData *dataObj = [NSData dataWithBytesNoCopy:(void *)data length:dataLength freeWhenDone:NO];

    for (NSString *pattern in knownPatterns) {
        NSData *pd = [pattern dataUsingEncoding:NSUTF8StringEncoding];
        if (pd && dataObj.length >= pd.length &&
            [dataObj rangeOfData:pd options:0 range:NSMakeRange(0, dataObj.length)].location != NSNotFound) {
            recordScan(@"已知密钥", [NSString stringWithFormat:@"[%s] 发现: %@", sourceLabel, pattern]);
        }
    }
}

#pragma mark - 扫描单个 Mach-O 段

static void ScanMachOSection(const struct mach_header_64 *header,
                               const char *segName, const char *sectName,
                               const char *sourceLabel) {
    unsigned long size = 0;
    const uint8_t *data = getsectiondata(header, segName, sectName, &size);
    if (!data || size == 0 || size > kMaxSectionScanSize) return;

    recordScan(@"段扫描", [NSString stringWithFormat:@"[%s] %s/%s: %lu 字节",
        sourceLabel, segName, sectName, (unsigned long)size]);

    // 1. 已知密钥
    ScanForKnownKeys(data, size, sourceLabel);

    // 2. 连续 hex 字符串（32/48/64 字符 = AES-128/192/256 密钥）
    ScanForHexStringSequences(data, size, sourceLabel, 32);

    // 3. Base64 编码密钥
    ScanForBase64Keys(data, size, sourceLabel);

    // 4. 密钥长度高熵块
    ScanForKeyLengthPatterns(data, size, sourceLabel);

    // 5. 大块高熵数据（可能是加密常量表）
    ScanForHighEntropyBlocks(data, size, sourceLabel, 7.8, 256, 4096);
}

#pragma mark - 扫描单个动态库的所有段

static void ScanDylibAtIndex(uint32_t index) {
    @autoreleasepool {
        const char *name = _dyld_get_image_name(index);
        if (!name) return;

        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(index);
        if (!header) return;

        NSString *libName = [NSString stringWithUTF8String:name];
        NSString *shortName = [libName lastPathComponent];
        const char *label = shortName.UTF8String;

        // __TEXT 段
        ScanMachOSection(header, "__TEXT", "__cstring", label);
        ScanMachOSection(header, "__TEXT", "__const", label);
        ScanMachOSection(header, "__TEXT", "__text", label);

        // __DATA 段
        ScanMachOSection(header, "__DATA", "__data", label);
        ScanMachOSection(header, "__DATA", "__bss", label);
        ScanMachOSection(header, "__DATA", "__common", label);

        // __DATA_CONST 段
        ScanMachOSection(header, "__DATA_CONST", "__const", label);
    }
}

#pragma mark - 堆内存扫描

static void ScanHeapMemory(void) {
    @autoreleasepool {
        @try {
            recordScan(@"堆扫描", @"开始扫描堆内存...");

            // 遍历所有 malloc zone 中的块
            vm_address_t *zones = NULL;
            unsigned int zoneCount = 0;
            kern_return_t kr = malloc_get_all_zones(0, 0, &zones, &zoneCount);
            if (kr != KERN_SUCCESS || !zones || zoneCount == 0) {
                recordScan(@"堆扫描", @"无法获取 malloc zones"];
                return;
            }

            NSUInteger totalScanned = 0;
            NSUInteger totalBlocks = 0;

            for (unsigned int z = 0; z < zoneCount; z++) {
                if (totalScanned >= kMaxHeapScanBytes) break;

                malloc_zone_t *zone = (malloc_zone_t *)zones[z];
                if (!zone || !zone->introspect) continue;

                // 使用 zone 的 enumerate 函数遍历所有块
                @try {
                    zone->introspect->enumerator(zone, &totalScanned, kMaxHeapScanBytes,
                        ^(malloc_zone_t *z, uintptr_t addr, uintptr_t size) {
                            @autoreleasepool {
                                if (size < 16 || size > 65536) return;  // 跳过太小或太大的块
                                if (totalScanned >= kMaxHeapScanBytes) return;

                                const uint8_t *data = (const uint8_t *)addr;

                                // 快速预检：跳过明显全 0 或全 FF 的块
                                uint8_t first = data[0];
                                BOOL allSame = YES;
                                NSUInteger checkLen = MIN((NSUInteger)size, (NSUInteger)64);
                                for (NSUInteger i = 1; i < checkLen; i++) {
                                    if (data[i] != first) { allSame = NO; break; }
                                }
                                if (allSame) return;

                                totalScanned += size;
                                totalBlocks++;

                                // 密钥长度高熵检测
                                ScanForKeyLengthPatterns(data, size, "堆内存");

                                // 如果块较大，扫 Base64
                                if (size >= 64) {
                                    ScanForBase64Keys(data, size, "堆内存");
                                }
                            }
                        });
                } @catch (NSException *e) {
                    // 某些 zone 的 enumerator 可能不兼容，跳过
                }
            }

            recordScan(@"堆扫描", [NSString stringWithFormat:
                @"完成，扫描了 %lu 个块，共 %lu 字节",
                (unsigned long)totalBlocks, (unsigned long)totalScanned]);
        } @catch (NSException *e) {
            recordScan(@"堆扫描异常", [NSString stringWithFormat:@"%@", e.reason]);
        }
    }
}

#pragma mark - 优先扫描目标库

static BOOL IsPriorityLib(const char *name) {
    if (!name) return NO;
    NSString *s = [NSString stringWithUTF8String:name];

    // 优先扫描 App 自身和 Flutter 引擎
    if ([s containsString:@".app/"]) return YES;
    if ([s containsString:@"libapp"]) return YES;
    if ([s containsString:@"libflutter"]) return YES;

    // 扫描常见的加密/网络库
    if ([s containsString:@"libcrypto"]) return YES;
    if ([s containsString:@"libssl"]) return YES;
    if ([s containsString:@"Security.framework"]) return YES;
    if ([s containsString:@"CommonCrypto"]) return YES;

    return NO;
}

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

    // 每 15 秒自动扫描一次，共 8 次（2 分钟内覆盖 App 运行周期）
    self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:15.0
                                                      target:self
                                                    selector:@selector(performMemoryScan)
                                                    userInfo:nil
                                                     repeats:YES];
    [self performMemoryScan];

    NSLog(@"[MemoryScan] 增强版内存扫描已启动");
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
    gResultsCount = 0;  // 重置计数器

    NSLog(@"[MemoryScan] 第 %lu 次扫描...", (unsigned long)self.scanCount);

    // 同步快速扫描
    [self scanUserDefaults];
    [self scanInfoPlist];

    // 异步深度扫描
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSLog(@"[MemoryScan] 开始异步深度扫描...");

        [self scanAllDylibs];
        [self scanHeapMemory];

        NSLog(@"[MemoryScan] 异步深度扫描完成 (本帧记录 %lu 条)", (unsigned long)gResultsCount);
    });

    if (self.scanCount >= 8) {
        [self stopScan];
    }
}

- (void)scanAllDylibs {
    @autoreleasepool {
        uint32_t imageCount = _dyld_image_count();
        recordScan(@"库扫描", [NSString stringWithFormat:@"共 %u 个动态库", imageCount]);

        // 第一轮：优先扫描目标库
        for (uint32_t i = 0; i < imageCount && gResultsCount < kMaxResultsPerScan; i++) {
            const char *name = _dyld_get_image_name(i);
            if (IsPriorityLib(name)) {
                ScanDylibAtIndex(i);
            }
        }

        // 第二轮：扫描剩余库（限制数量，防止太慢）
        NSUInteger scannedOthers = 0;
        for (uint32_t i = 0; i < imageCount && scannedOthers < 20 && gResultsCount < kMaxResultsPerScan; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!IsPriorityLib(name)) {
                ScanDylibAtIndex(i);
                scannedOthers++;
            }
        }
    }
}

- (void)scanLoadedLibraries {
    // 兼容旧调用入口
    [self scanAllDylibs];
}

- (void)scanProcessMemory {
    // 兼容旧调用入口
    [self scanAllDylibs];
    [self scanHeapMemory];
}

// ─── 保留原有功能 ───

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

@end
