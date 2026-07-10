#import <Foundation/Foundation.h>

@interface UCMemoryScanManager : NSObject

+ (instancetype)sharedManager;

- (void)startScan;
- (void)stopScan;
- (void)scanAllDylibs;
- (void)scanLoadedLibraries;  // 兼容旧入口
- (void)scanProcessMemory;    // 兼容旧入口

@end
