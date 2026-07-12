#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * PointCastleHook 管理器。
 *
 * MDTV 使用 Flutter + pointycastle 进行 AES 加密，密钥在 Dart 层生成，
 * 不经过 iOS CommonCrypto，因此 FLEX 原有的 CCCrypt hook 无法捕获。
 *
 * 本模块通过 hook NSURLSession 的 dataTaskWithRequest:/dataTaskWithURL:
 * （无 completionHandler 版本）工作：
 * 1. 每次 task 创建时，通过 session.delegate 找到原始 delegate
 * 2. Swizzle 其 didReceiveData: / didCompleteWithError: 方法
 * 3. 累积响应数据，完成后检测 MDTV {"suffix":"...","data":"..."} 格式
 * 4. 触发 Dart 堆内存扫描，提取 AES 密钥候选并用捕获的密文进行验证
 *
 * 优势：无论 Flutter 的 NSURLSession 何时创建，都能在首次请求时拦截。
 */
@interface UCPointCastleHookManager : NSObject

+ (instancetype)sharedManager;

/**
 * 安装 NSURLSession dataTask hook。
 * 完全独立于 URLCapture.m，不依赖总开关状态。
 */
- (void)installHooks;

/**
 * 由 swizzled delegate 方法在收到解密后的 HTTP 响应时调用。
 * 检测是否包含 MDTV {"suffix":"...","data":"..."} 格式，并触发扫描。
 */
+ (void)handleDecryptedResponse:(NSData *)body;

/**
 * 手动触发一次"捕获响应 + 扫描 + 验证"流程（调试用）。
 */
- (void)triggerValidationWithResponseBody:(NSData *)responseBody;

@end

NS_ASSUME_NONNULL_END