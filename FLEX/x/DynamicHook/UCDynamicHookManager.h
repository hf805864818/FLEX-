#import <Foundation/Foundation.h>

@interface UCDynamicHookManager : NSObject

+ (instancetype)sharedManager;

- (void)installHooks;

@end
