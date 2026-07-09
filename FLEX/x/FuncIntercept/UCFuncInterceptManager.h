#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface UCFuncInterceptManager : NSObject

+ (instancetype)sharedManager;

- (void)installHooks;

@end

NS_ASSUME_NONNULL_END
