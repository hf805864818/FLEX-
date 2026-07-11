#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * PointCastleHook 管理器。
 *
 * MDTV 使用 Flutter + pointycastle 进行 AES 加密，密钥在 Dart 层生成，
 * 不经过 iOS CommonCrypto，因此 FLEX 原有的 CCCrypt hook 无法捕获。
 *
 * 本模块通过 URLCapture.m 的 NSURLSession hook 获取解密后的 HTTP 响应明文，
 * 检测 MDTV 的 {"suffix":"...","data":"..."} 格式，触发 Dart 堆内存扫描，
 * 提取 AES 密钥候选并用捕获的密文进行实时验证。
 */
@interface UCPointCastleHookManager : NSObject

+ (instancetype)sharedManager;

/**
 * 安装 hooks（保留兼容性，现在主要工作由 URLCapture.m 完成）。
 */
- (void)installHooks;

/**
 * 由 URLCapture.m 在收到解密后的 HTTP 响应时调用。
 * 检测是否包含 MDTV {"suffix":"...","data":"..."} 格式，并触发扫描。
 */
+ (void)handleDecryptedResponse:(NSData *)body;

/**
 * 手动触发一次"捕获响应 + 扫描 + 验证"流程（调试用）。
 */
- (void)triggerValidationWithResponseBody:(NSData *)responseBody;

@end

NS_ASSUME_NONNULL_END