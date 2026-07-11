#import "UCDartMemoryScanner.h"
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach-o/dyld.h>
#import <CommonCrypto/CommonDigest.h>

// 单次扫描上限：防止 OOM 或拖垮主线程
static const NSUInteger kDefaultMaxScanBytes = 80 * 1024 * 1024;  // 80 MB
static const NSUInteger kMinRegionSize = 1024;                      // 小于 1KB 的区域忽略

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

    [self enumerateReadableWritableRegionsUsingBlock:^(const void *base, size_t size, BOOL *stop) {
        if (size < kMinRegionSize) return;
        if (size > kDefaultMaxScanBytes) size = kDefaultMaxScanBytes;

        const uint8_t *bytes = (const uint8_t *)base;
        NSUInteger keyLengths[] = {16, 24, 32};

        for (NSUInteger ki = 0; ki < 3; ki++) {
            NSUInteger keyLen = keyLengths[ki];
            if (size < keyLen) continue;

            for (NSUInteger offset = 0; offset <= size - keyLen; offset++) {
                // 步长优化：AES 密钥通常按 16 字节对齐或紧跟在 Dart 对象头后
                // 但为了不错过，只在发现候选时按字节滑动；未通过熵/可打印测试时跳 4 字节
                if ((offset % 4) != 0) continue;

                NSData *candidate = [NSData dataWithBytes:bytes + offset length:keyLen];
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
    }];

    return [candidates copy];
}

#pragma mark - 内存区域枚举

- (void)enumerateReadableWritableRegionsUsingBlock:(void (^)(const void *base, size_t size, BOOL *stop))block {
    if (!block) return;

    task_t task = mach_task_self();
    vm_address_t address = 0;
    vm_size_t size = 0;
    kern_return_t kr = KERN_SUCCESS;

    while (kr == KERN_SUCCESS) {
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t info;
        memory_object_name_t objectName = MACH_PORT_NULL;

        kr = vm_region_64(task,
                          &address,
                          &size,
                          VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info,
                          &count,
                          &objectName);
        if (kr != KERN_SUCCESS) break;

        // 只扫描可读可写（RW）区域；排除只读 text 段
        BOOL isReadable = (info.protection & VM_PROT_READ) != 0;
        BOOL isWritable = (info.protection & VM_PROT_WRITE) != 0;
        // Dart 堆通常为 VM_PROT_READ | VM_PROT_WRITE，且不是共享的
        BOOL isShared = (info.shared != 0);

        if (isReadable && isWritable && !isShared && size >= kMinRegionSize) {
            BOOL stop = NO;
            block((const void *)address, (size_t)size, &stop);
            if (stop) break;
        }

        address += size;
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
