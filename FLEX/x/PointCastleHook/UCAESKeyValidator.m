#import "UCAESKeyValidator.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation UCAESKeyValidator

+ (NSArray<NSString *> *)supportedModes {
    return @[@"cbc", @"cfb", @"ctr", @"ofb", @"ecb"];
}

+ (nullable NSData *)validateKey:(NSData *)keyData
                    ciphertext:(NSData *)ciphertext
                            iv:(nullable NSData *)ivData
                          mode:(NSString *)mode {
    if (!keyData || keyData.length != kCCKeySizeAES128 &&
        keyData.length != kCCKeySizeAES192 && keyData.length != kCCKeySizeAES256) {
        return nil;
    }
    if (!ciphertext || ciphertext.length == 0 || ciphertext.length % kCCBlockSizeAES128 != 0) {
        return nil;
    }

    NSString *low = [mode lowercaseString];

    // CBC/ECB 用 CCCrypt 原生支持
    if ([low isEqualToString:@"cbc"]) {
        if (!ivData || ivData.length != kCCBlockSizeAES128) return nil;
        return [self decryptWithAlgorithm:kCCAlgorithmAES
                                  options:kCCOptionPKCS7Padding
                                      key:keyData
                                       iv:ivData
                              ciphertext:ciphertext];
    }

    if ([low isEqualToString:@"ecb"]) {
        return [self decryptWithAlgorithm:kCCAlgorithmAES
                                  options:kCCOptionPKCS7Padding | kCCOptionECBMode
                                      key:keyData
                                       iv:nil
                              ciphertext:ciphertext];
    }

    // CFB/CTR/OFB CommonCrypto 不直接支持，用自实现节段模式（Segmented / CFB-128 / OFB-128 / CTR）
    if ([low isEqualToString:@"cfb"]) {
        if (!ivData || ivData.length != kCCBlockSizeAES128) return nil;
        return [self decryptCFB128WithKey:keyData iv:ivData ciphertext:ciphertext];
    }
    if ([low isEqualToString:@"ofb"]) {
        if (!ivData || ivData.length != kCCBlockSizeAES128) return nil;
        return [self decryptOFBWithKey:keyData iv:ivData ciphertext:ciphertext];
    }
    if ([low isEqualToString:@"ctr"]) {
        if (!ivData || ivData.length != kCCBlockSizeAES128) return nil;
        return [self decryptCTRWithKey:keyData iv:ivData ciphertext:ciphertext];
    }

    return nil;
}

#pragma mark - CommonCrypto CBC/ECB

+ (nullable NSData *)decryptWithAlgorithm:(CCAlgorithm)algorithm
                                  options:(CCOptions)options
                                      key:(NSData *)key
                                       iv:(nullable NSData *)iv
                              ciphertext:(NSData *)ciphertext {
    size_t bufferSize = ciphertext.length + kCCBlockSizeAES128;
    NSMutableData *outData = [NSMutableData dataWithLength:bufferSize];
    size_t moved = 0;

    CCCryptorStatus status = CCCrypt(kCCDecrypt,
                                     algorithm,
                                     options,
                                     key.bytes,
                                     key.length,
                                     iv.bytes,
                                     ciphertext.bytes,
                                     ciphertext.length,
                                     outData.mutableBytes,
                                     bufferSize,
                                     &moved);
    if (status != kCCSuccess) return nil;

    outData.length = moved;
    if ([self looksLikeValidPlaintext:outData]) {
        return outData;
    }
    return nil;
}

#pragma mark - CFB-128 / OFB / CTR 自实现

// 用 ECB（无填充）加密单个 block，得到 keystream
+ (NSData *)encryptBlockECB:(NSData *)block key:(NSData *)key {
    if (!block || block.length != kCCBlockSizeAES128) return nil;
    NSMutableData *outData = [NSMutableData dataWithLength:kCCBlockSizeAES128];
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(kCCEncrypt,
                                     kCCAlgorithmAES,
                                     kCCOptionECBMode,
                                     key.bytes,
                                     key.length,
                                     NULL,
                                     block.bytes,
                                     block.length,
                                     outData.mutableBytes,
                                     outData.length,
                                     &moved);
    if (status != kCCSuccess) return nil;
    return outData;
}

+ (nullable NSData *)decryptCFB128WithKey:(NSData *)key
                                       iv:(NSData *)iv
                              ciphertext:(NSData *)ciphertext {
    NSMutableData *plain = [NSMutableData dataWithLength:ciphertext.length];
    NSData *prev = iv;
    NSUInteger len = ciphertext.length;
    NSUInteger blockSize = kCCBlockSizeAES128;

    for (NSUInteger offset = 0; offset < len; offset += blockSize) {
        NSData *keystream = [self encryptBlockECB:prev key:key];
        if (!keystream) return nil;

        NSUInteger chunk = MIN(blockSize, len - offset);
        const uint8_t *c = (const uint8_t *)ciphertext.bytes + offset;
        const uint8_t *k = (const uint8_t *)keystream.bytes;
        uint8_t *p = (uint8_t *)plain.mutableBytes + offset;
        for (NSUInteger i = 0; i < chunk; i++) {
            p[i] = c[i] ^ k[i];
        }

        // CFB-128 反馈：用原始密文 block 作为下一轮的 prev（不足 blockSize 时补齐）
        NSMutableData *feedback = [NSMutableData dataWithLength:blockSize];
        memset(feedback.mutableBytes, 0, blockSize);
        memcpy(feedback.mutableBytes, c, chunk);
        prev = feedback;
    }

    if ([self looksLikeValidPlaintext:plain]) return plain;
    return nil;
}

+ (nullable NSData *)decryptOFBWithKey:(NSData *)key
                                    iv:(NSData *)iv
                           ciphertext:(NSData *)ciphertext {
    NSMutableData *plain = [NSMutableData dataWithLength:ciphertext.length];
    NSData *prev = iv;
    NSUInteger len = ciphertext.length;
    NSUInteger blockSize = kCCBlockSizeAES128;

    for (NSUInteger offset = 0; offset < len; offset += blockSize) {
        NSData *keystream = [self encryptBlockECB:prev key:key];
        if (!keystream) return nil;

        NSUInteger chunk = MIN(blockSize, len - offset);
        const uint8_t *c = (const uint8_t *)ciphertext.bytes + offset;
        const uint8_t *k = (const uint8_t *)keystream.bytes;
        uint8_t *p = (uint8_t *)plain.mutableBytes + offset;
        for (NSUInteger i = 0; i < chunk; i++) {
            p[i] = c[i] ^ k[i];
        }

        prev = keystream; // OFB 反馈的是 keystream
    }

    if ([self looksLikeValidPlaintext:plain]) return plain;
    return nil;
}

+ (nullable NSData *)decryptCTRWithKey:(NSData *)key
                                    iv:(NSData *)iv
                           ciphertext:(NSData *)ciphertext {
    NSMutableData *plain = [NSMutableData dataWithLength:ciphertext.length];
    NSUInteger len = ciphertext.length;
    NSUInteger blockSize = kCCBlockSizeAES128;

    // IV 作为初始计数器（16 字节大端整数，每 block +1）
    uint8_t counter[blockSize];
    memcpy(counter, iv.bytes, blockSize);

    for (NSUInteger offset = 0; offset < len; offset += blockSize) {
        NSData *counterData = [NSData dataWithBytes:counter length:blockSize];
        NSData *keystream = [self encryptBlockECB:counterData key:key];
        if (!keystream) return nil;

        NSUInteger chunk = MIN(blockSize, len - offset);
        const uint8_t *c = (const uint8_t *)ciphertext.bytes + offset;
        const uint8_t *k = (const uint8_t *)keystream.bytes;
        uint8_t *p = (uint8_t *)plain.mutableBytes + offset;
        for (NSUInteger i = 0; i < chunk; i++) {
            p[i] = c[i] ^ k[i];
        }

        // 计数器 +1（大端）
        for (NSInteger i = blockSize - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }

    if ([self looksLikeValidPlaintext:plain]) return plain;
    return nil;
}

#pragma mark - 多模式尝试

+ (nullable NSDictionary *)validateKeyAcrossModes:(NSData *)keyData
                                     ciphertext:(NSData *)ciphertext
                                             iv:(nullable NSData *)ivData {
    for (NSString *mode in [self supportedModes]) {
        NSData *plain = [self validateKey:keyData ciphertext:ciphertext iv:ivData mode:mode];
        if (plain) {
            return @{
                @"mode": mode,
                @"plaintext": plain
            };
        }
    }
    return nil;
}

#pragma mark - 明文校验

+ (BOOL)looksLikeValidPlaintext:(NSData *)data {
    if (!data || data.length == 0) return NO;

    // 优先判断是否为有效的 JSON
    NSError *error = nil;
    id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (json && ([json isKindOfClass:[NSDictionary class]] || [json isKindOfClass:[NSArray class]])) {
        return YES;
    }

    // 退而求其次：可打印 UTF-8 字符串且包含常见 MDTV 字段
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text) return NO;

    // 可见字符比例要够高
    NSUInteger printable = 0;
    NSUInteger total = text.length;
    if (total == 0) return NO;
    for (NSUInteger i = 0; i < total; i++) {
        unichar c = [text characterAtIndex:i];
        if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') {
            printable++;
        }
    }
    if ((double)printable / (double)total < 0.85) return NO;

    // MDTV 常见字段
    NSArray *hints = @[@"code", @"message", @"data", @"post-data", @"suffix", @"JGDZMX", @"nzp1ve"];
    for (NSString *hint in hints) {
        if ([text rangeOfString:hint options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }

    return NO;
}

@end
