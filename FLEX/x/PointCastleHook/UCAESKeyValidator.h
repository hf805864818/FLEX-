#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * AES 密钥验证器：使用 CommonCrypto 尝试多种 AES 模式/填充，
 * 验证从 Dart 内存中扫描出的候选密钥是否能解密 MDTV 响应体。
 */
@interface UCAESKeyValidator : NSObject

/**
 * 支持的 AES 工作模式（小写）。
 */
+ (NSArray<NSString *> *)supportedModes;

/**
 * 尝试用候选密钥解密一段密文。
 *
 * @param keyData     候选密钥（16/24/32 字节）
 * @param ciphertext  密文（base64 解码后的原始 bytes）
 * @param ivData      初始向量（CBC/CFB/CTR/OFB 需要；ECB 可传 nil）
 * @param mode        AES 模式：cbc、cfb、ctr、ofb、ecb
 * @return 解密后且通过 JSON/UTF8 校验的 NSData；若失败返回 nil
 */
+ (nullable NSData *)validateKey:(NSData *)keyData
                    ciphertext:(NSData *)ciphertext
                            iv:(nullable NSData *)ivData
                          mode:(NSString *)mode;

/**
 * 便捷方法：依次尝试所有支持的模式，返回第一个能解出合理明文的结果。
 *
 * @param keyData     候选密钥
 * @param ciphertext  密文
 * @param ivData      初始向量（可为 nil，ECB/CTR 部分实现会忽略）
 * @return 字典 @{ @"mode": mode, @"plaintext": NSData }；失败返回 nil
 */
+ (nullable NSDictionary *)validateKeyAcrossModes:(NSData *)keyData
                                     ciphertext:(NSData *)ciphertext
                                             iv:(nullable NSData *)ivData;

/**
 * 判断一段数据是否像有效的 MDTV 响应明文（JSON 对象/数组，或包含常见字段）。
 */
+ (BOOL)looksLikeValidPlaintext:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
