#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * PointCastleHook 管理器。
 *
 * MDTV 使用 Flutter + pointycastle 进行 AES 加密，密钥在 Dart 层生成，
 * 不经过 iOS CommonCrypto，因此 FLEX 原有的 CCCrypt hook 无法捕获。
 *
 * 本模块通过 NSURLSession Delegate 代理拦截方案工作：
 * 1. Hook NSURLSession 的 initWithConfiguration:delegate:delegateQueue:
 *    和 sessionWithConfiguration:delegate:delegateQueue: 方法
 * 2. 在 delegate 和 NSURLSession 之间插入 UCPointCastleDelegateProxy
 * 3. 代理拦截 didReceiveData / didCompleteWithError 获取明文响应
 * 4. 检测 MDTV 的 {"suffix":"...","data":"..."} 格式
 * 5. 触发 Dart 堆内存扫描，提取 AES 密钥候选并用捕获的密文进行验证
 */
@interface UCPointCastleHookManager : NSObject

+ (instancetype)sharedManager;

/**
 * 安装 NSURLSession delegate 代理 hooks。
 * 完全独立于 URLCapture.m，不依赖总开关状态。
 */
- (void)installHooks;

/**
 * 由 delegate 代理在收到解密后的 HTTP 响应时调用。
 * 检测是否包含 MDTV {"suffix":"...","data":"..."} 格式，并触发扫描。
 */
+ (void)handleDecryptedResponse:(NSData *)body;

/**
 * 手动触发一次"捕获响应 + 扫描 + 验证"流程（调试用）。
 */
- (void)triggerValidationWithResponseBody:(NSData *)responseBody;

@end

NS_ASSUME_NONNULL_END