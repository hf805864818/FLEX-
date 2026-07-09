#import "UCMemoryScanManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <mach/mach.h>
#import <malloc/malloc.h>
#import <objc/runtime.h>

static const size_t kMaxScanSize = 4 * 1024 * 1024; // 4MB 上限

static void recordScan(NSString *matchType, NSString *value) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@", matchType, value];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"memory_scan"
                                                bundleID:bundleID
                                                    text:text];
}

@interface UCMemoryScanManager ()
@property (nonatomic, assign) BOOL isScanning;
@property (nonatomic, strong) NSTimer *scanTimer;
@property (nonatomic, assign) NSUInteger scanCount;
@end

@implementation UCMemoryScanManager

+ (instancetype)sharedManager {
    static UCMemoryScanManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCMemoryScanManager alloc] init];
    });
    return instance;
}

- (void)startScan {
    if (self.isScanning) return;
    self.isScanning = YES;
    self.scanCount = 0;

    // 每10秒自动扫描一次，共6次
    self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:10.0
                                                      target:self
                                                    selector:@selector(performMemoryScan)
                                                    userInfo:nil
                                                     repeats:YES];
    [self performMemoryScan]; // 立即执行第一次

    NSLog(@"[MemoryScan] 内存扫描已启动");
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
    NSLog(@"[MemoryScan] 第 %lu 次扫描...", (unsigned long)self.scanCount);

    // 扫描所有已注册的 Objective-C 类，查找可疑数据
    [self scanRegisteredClasses];

    // 扫描 NSUserDefaults 中的敏感 key
    [self scanUserDefaults];

    // 扫描 Info.plist 中的敏感信息
    [self scanInfoPlist];

    if (self.scanCount >= 6) {
        [self stopScan];
    }
}

- (void)scanRegisteredClasses {
    unsigned int classCount = 0;
    Class *classList = objc_copyClassList(&classCount);

    for (unsigned int i = 0; i < classCount && i < 500; i++) {
        Class cls = classList[i];
        NSString *className = NSStringFromClass(cls);

        // 跳过系统类，只关注第三方/App 类
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
            [className hasPrefix:@"AS"]) {
            continue;
        }

        // 检查类方法中是否包含加密相关关键词
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        BOOL hasCrypto = NO;

        for (unsigned int j = 0; j < methodCount && j < 100; j++) {
            NSString *methodName = NSStringFromSelector(method_getName(methods[j]));
            NSString *low = methodName.lowercaseString;
            if ([low containsString:@"encrypt"] || [low containsString:@"decrypt"] ||
                [low containsString:@"aes"] || [low containsString:@"des"] ||
                [low containsString:@"crypto"] || [low containsString:@"key"] ||
                [low containsString:@"sign"] || [low containsString:@"hash"] ||
                [low containsString:@"token"]) {
                hasCrypto = YES;
                break;
            }
        }
        free(methods);

        if (hasCrypto) {
            recordScan(@"加密常量", [NSString stringWithFormat:@"类 %@ 包含加密方法", className]);
        }
    }
    free(classList);
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
            recordScan(@"密钥格式", [NSString stringWithFormat:@"Info.plist[%@] = %@", key, val ? [NSString stringWithFormat:@"%@", val] : @"(nil)"]);
        }
    }
}

@end
