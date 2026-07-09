#import <Foundation/Foundation.h>

@interface UCMemoryScanManager : NSObject

+ (instancetype)sharedManager;

- (void)startScan;
- (void)stopScan;
- (void)scanLoadedLibraries;  // ★ 新增：扫描加载的动态库内存

@end
