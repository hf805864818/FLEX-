#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Dart 堆内存扫描器。
 *
 * Flutter / Dart 使用自己的堆管理器（Dart VM isolate heap）。
 * 本类遍历当前进程可读写的内存区域，提取长度符合 AES 密钥（16/24/32 字节）
 * 的连续数据块，并按简单启发规则过滤，返回候选密钥列表。
 */
@interface UCDartMemoryScanner : NSObject

+ (instancetype)sharedScanner;

/**
 * 扫描 Dart 堆内存，返回候选 AES 密钥。
 *
 * @param maxCandidates 最多返回的候选数（默认 200）
 * @param completion    回调在主线程执行，参数为候选 NSData 数组
 */
- (void)scanForAESKeyCandidates:(NSUInteger)maxCandidates
                     completion:(void (^)(NSArray<NSData *> *candidates))completion;

/**
 * 同步扫描（阻塞当前线程，仅用于确定在主线程外调用）。
 */
- (NSArray<NSData *> *)scanForAESKeyCandidatesSync:(NSUInteger)maxCandidates;

@end

NS_ASSUME_NONNULL_END
