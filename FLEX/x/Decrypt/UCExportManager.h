#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface UCExportManager : NSObject

+ (void)exportItems:(NSArray<NSDictionary *> *)items
          tableName:(NSString *)tableName
 fromViewController:(UIViewController *)vc
         completion:(void(^_Nullable)(BOOL success))completion;

+ (void)exportNetworkTransactions:(NSArray *)transactions
               fromViewController:(UIViewController *)vc
                       completion:(void(^_Nullable)(BOOL success))completion;

@end

NS_ASSUME_NONNULL_END
