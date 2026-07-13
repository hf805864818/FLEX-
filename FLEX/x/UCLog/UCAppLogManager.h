#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface UCAppLogManager : NSObject

+ (instancetype)sharedManager;

@property (nonatomic, assign) NSInteger maxLogCount;      // 默认 5000
@property (nonatomic, assign) NSInteger maxLogDays;       // 默认 7，0 表示不限制
@property (nonatomic, assign) BOOL captureNSLog;          // 默认 YES
@property (nonatomic, assign) BOOL captureOSLog;          // 默认 YES

@property (nonatomic, strong) id osLogController;

- (void)startCapture;
- (void)startCaptureIfEnabled;
- (void)stopCapture;

- (BOOL)isCaptureEnabled;
- (void)enqueueLog:(NSString *)msg;

- (NSArray<NSDictionary *> *)allLogs;
- (NSArray<NSDictionary *> *)logsWithLimit:(NSInteger)limit;

- (void)deleteLogById:(NSInteger)logId;
- (void)clearAllLogs;
- (void)cleanupIfNeeded;

- (void)exportAllLogsFromViewController:(UIViewController *)vc completion:(void(^_Nullable)(BOOL success))completion;
- (void)exportLogRecord:(NSDictionary *)record fromViewController:(UIViewController *)vc completion:(void(^_Nullable)(BOOL success))completion;

@end

NS_ASSUME_NONNULL_END
