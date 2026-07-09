#import <Foundation/Foundation.h>

@interface UCMemoryScanManager : NSObject

+ (instancetype)sharedManager;

- (void)startScan;
- (void)stopScan;

@end
