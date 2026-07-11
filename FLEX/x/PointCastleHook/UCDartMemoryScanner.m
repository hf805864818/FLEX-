#import "UCDartMemoryScanner.h"
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach-o/dyld.h>
#import <CommonCrypto/CommonDigest.h>

// 单次扫描上限：防止 OOM 或拖垮主线程
static const NSUInteger kDefaultMaxScanBytes = 30 * 1024 * 1024;  // 30 MB（降低避免 Jetsam）
static const NSUInteger kMinRegionSize = 1024;                     // 小于 1KB 的区域忽略
static const vm_size_t kScanChunkSize = 256 * 1024;                // 分块 256KB 安全读取

@interface UCDartMemoryScanner ()
@property (nonatomic, strong) dispatch_queue_t scanQueue;
@end

@implementation UCDartMemoryScanner

+ (instancetype)sharedScanner {
    static UCDartMemoryScanner *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _scanQueue = dispatch_queue_create("com.flex.pointycastle.scan", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

#pragma mark - 公共入口

- (void)scanForAESKeyCandidates:(NSUInteger)maxCandidates
                     completion:(void (^)(NSArray<NSData *> *candidates))completion {
    dispatch_async(self.scanQueue, ^{
        NSArray *results = [self scanForAESKeyCandidatesSync:maxCandidates];
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(results);
            });
        }
    });
}

- (NSArray<NSData *> *)scanForAESKeyCandidatesSync:(NSUInteger)maxCandidates {
    if (maxCandidates == 0) maxCandidates = 200;

    NSMutableSet<NSData *> *unique = [NSMutableSet set];
    NSMutableArray<NSData *> *candidates = [NSMutableArray array];
    __block NSUInteger remainingBudget = kDefaultMaxScanBytes;

    [self enumerateReadableWritableRegionsUsingBlock:^(vm_address_t address, vm_size_t regionSize, BOOL *stop) {
        if (regionSize < kMinRegionSize) return;
        if (remainingBudget == 0) { *stop = YES; return; }

        vm_size_t scanSize = MIN(regionSize, (vm_size_t)remainingBudget);

        // 分块安全读取，避免直接访问可能失效的映射
        vm_size_t offset = 0;
        while (offset < scanSize && candidates.count < maxCandidates) {
            vm_size_t chunkSize = MIN(kScanChunkSize, scanSize - offset);
            if (chunkSize == 0) break;

            uint8_t *buffer = (uint8_t *)malloc(chunkSize);
            if (!buffer) break;

            vm_size_t bytesRead = 0;
            kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                                   address + offset,
                                                   chunkSize,
                                                   (vm_address_t)buffer,
                                                   &bytesRead);
            if (kr == KERN_SUCCESS && bytesRead == chunkSize) {
                [self scanBuffer:buffer
                          length:(NSUInteger)bytesRead
                   maxCandidates:maxCandidates
                          unique:unique
                      candidates:candidates
                            stop:stop];
                remainingBudget -= bytesRead;
            }

            free(buffer);
            offset += chunkSize;

            if (*stop) break;
        }
    }];

    return [candidates copy];
}

#pragma mark - 内存区域枚举

- (void)enumerateReadableWritableRegionsUsingBlock:(void (^)(vm_address_t address, vm_size_t size, BOOL *stop))block {
    if (!block) return;

    task_t task = mach_task_self();
    vm_address_t address = 0;
    vm_size_t size = 0;
    natural_t nestingLevel = 0;
    struct vm_region_submap_info_64 submapInfo;
    mach_msg_type_number_t infoCount = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = KERN_SUCCESS;

    while (kr == KERN_SUCCESS) {
        kr = vm_region_recurse_64(task, &address, &size, &nestingLevel,
                                  (vm_region_recurse_info_t)&submapInfo, &infoCount);
        if (kr != KERN_SUCCESS) break;

        if (submapInfo.is_submap) {
            nestingLevel++;
            continue;
        }
        if (nestingLevel > 0) nestingLevel--;

        // 只扫描可读可写（RW）区域；排除共享映射
        BOOL isReadable = (submapInfo.protection & VM_PROT_READ) != 0;
        BOOL isWritable = (submapInfo.protection & VM_PROT_WRITE) != 0;
        BOOL maxReadable = (submapInfo.max_protection & VM_PROT_READ) != 0;
        BOOL maxWritable = (submapInfo.max_protection & VM_PROT_WRITE) != 0;

        if (isReadable && isWritable && maxReadable && maxWritable && size >= kMinRegionSize) {
            BOOL stop = NO;
            block(address, size, &stop);
            if (stop) break;
        }

        address += size;
    }
}

#pragma mark - 扫描缓冲区

- (void)scanBuffer:(const uint8_t *)buffer
            length:(NSUInteger)length
     maxCandidates:(NSUInteger)maxCandidates
            unique:(NSMutableSet<NSData *> *)unique
        candidates:(NSMutableArray<NSData *> *)candidates
              stop:(BOOL *)stop {
    if (!buffer || length < 16) return;

    NSUInteger keyLengths[] = {16, 24, 32};

    for (NSUInteger ki = 0; ki < 3; ki++) {
        NSUInteger keyLen = keyLengths[ki];
        if (length < keyLen) continue;

        for (NSUInteger offset = 0; offset <= length - keyLen; offset++) {
            // 步长优化：未通过测试时按 4 字节跳跃
            if ((offset % 4) != 0) continue;

            NSData *candidate = [NSData dataWithBytes:buffer + offset length:keyLen];
            if ([unique containsObject:candidate]) continue;

            if (![self isPromisingCandidate:candidate]) continue;

            [unique addObject:candidate];
            [candidates addObject:candidate];

            if (candidates.count >= maxCandidates) {
                *stop = YES;
                return;
            }
        }
    }
}

#pragma mark - 候选过滤

- (BOOL)isPromisingCandidate:(NSData *)data {
    if (!data || data.length == 0) return NO;

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;

    // 1. 拒绝全 0 / 全 0xFF
    BOOL allZero = YES, allFF = YES;
    for (NSUInteger i = 0; i < len; i++) {
        if (bytes[i] != 0x00) allZero = NO;
        if (bytes[i] != 0xFF) allFF = NO;
        if (!allZero && !allFF) break;
    }
    if (allZero || allFF) return NO;

    // 2. 计算 Shannon 熵，排除极低熵（如大量重复字符）或极高熵（已加密随机数）
    double entropy = [self shannonEntropyOfData:data];
    if (entropy < 2.5 || entropy > 7.8) return NO;

    // 3. 如果是纯可打印 ASCII/UTF-8 字符串，认为是潜在字符串密钥
    NSString *utf8 = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (utf8 && utf8.length > 0) {
        BOOL allPrintable = YES;
        for (NSUInteger i = 0; i < utf8.length; i++) {
            unichar c = [utf8 characterAtIndex:i];
            if (c < 0x20 || c > 0x7E) {
                allPrintable = NO;
                break;
            }
        }
        if (allPrintable) return YES;
    }

    // 4. 允许高熵二进制密钥，但要求至少一半字节非零且分布不太集中
    NSUInteger nonZero = 0;
    for (NSUInteger i = 0; i < len; i++) {
        if (bytes[i] != 0) nonZero++;
    }
    if ((double)nonZero / (double)len < 0.7) return NO;

    return YES;
}

- (double)shannonEntropyOfData:(NSData *)data {
    if (!data || data.length == 0) return 0.0;
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;

    NSUInteger freq[256] = {0};
    for (NSUInteger i = 0; i < len; i++) {
        freq[bytes[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

@end
