#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * PointCastleHook 管理器。
 *
 * MDTV 使用 Flutter + pointycastle 进行 AES 加密，密钥在 Dart 层生成，
 * 不经过 iOS CommonCrypto，因此 FLEX 原有的 CCCrypt hook 无法捕获。
 *
 * 本模块通过 hook POSIX socket 函数检测 Flutter 网络流量（api.nzp1ve.com），
 * 在收到响应后触发 Dart 堆内存扫描，提取可能的 AES 密钥候选，并用捕获到的
 * 响应密文进行实时验证。验证通过的密钥会写入 pointycastle_keys 表。
 */
@interface UCPointCastleHookManager : NSObject

+ (instancetype)sharedManager;

/**
 * 安装 socket hooks。应在 UCDecryptTool 初始化时调用一次。
 */
- (void)installHooks;

/**
 * 手动触发一次“捕获响应 + 扫描 + 验证”流程（调试用）。
 */
- (void)triggerValidationWithResponseBody:(NSData *)responseBody;

@end

NS_ASSUME_NONNULL_END
