#import <Foundation/Foundation.h>

@interface UCMemoryScanManager : NSObject

@property (nonatomic, strong) NSTimer *scanTimer;
@property (nonatomic, assign) BOOL isScanning;
@property (nonatomic, assign) NSUInteger scanCount;

+ (instancetype)sharedManager;

- (void)startScan;
- (void)stopScan;
- (void)performMemoryScan;
- (void)scanAllDylibs;
- (void)scanLoadedLibraries;  // 兼容旧入口
- (void)scanProcessMemory;    // 兼容旧入口
- (void)scanHeapMemory;

@end
