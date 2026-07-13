#import "UCAppLogManager.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/UCExportManager.h"
#import "FLEXOSLogController.h"
#import "FLEXSystemLogMessage.h"
#import "flex_fishhook.h"
#import <UIKit/UIKit.h>
#include <stdarg.h>

static NSString * const kUCAppLogMaxCountKey = @"UCAppLogMaxCount";
static NSString * const kUCAppLogMaxDaysKey  = @"UCAppLogMaxDays";
static NSString * const kUCAppLogCaptureNSLogKey = @"UCAppLogCaptureNSLog";
static NSString * const kUCAppLogCaptureOSLogKey = @"UCAppLogCaptureOSLog";

static void (*orig_NSLogv)(NSString *format, va_list args);
static void uc_NSLogv(NSString *format, va_list args) {
    if (orig_NSLogv) orig_NSLogv(format, args);
    if (!format) return;
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    if (msg.length > 0) {
        [[UCAppLogManager sharedManager] enqueueLog:msg];
    }
}

@interface UCAppLogManager ()
@property (nonatomic, strong) dispatch_queue_t logQueue;
@property (nonatomic, strong) NSMutableArray<NSString *> *pendingLogs;
@property (nonatomic, strong) NSTimer *flushTimer;
@property (nonatomic, strong) NSTimer *cleanupTimer;
@property (nonatomic, assign) BOOL isCapturing;
@end

@implementation UCAppLogManager

+ (instancetype)sharedManager {
    static UCAppLogManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCAppLogManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _logQueue = dispatch_queue_create("com.ucflex.applog.queue", DISPATCH_QUEUE_SERIAL);
        _pendingLogs = [NSMutableArray array];
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        _maxLogCount = [ud integerForKey:kUCAppLogMaxCountKey];
        if (_maxLogCount <= 0) _maxLogCount = 5000;
        _maxLogDays = [ud integerForKey:kUCAppLogMaxDaysKey];
        if (_maxLogDays <= 0) _maxLogDays = 7;
        // 默认只开 NSLog hook，OSLog 更耗性能，需要手动开
        _captureNSLog = [ud objectForKey:kUCAppLogCaptureNSLogKey] ? [ud boolForKey:kUCAppLogCaptureNSLogKey] : YES;
        _captureOSLog = [ud objectForKey:kUCAppLogCaptureOSLogKey] ? [ud boolForKey:kUCAppLogCaptureOSLogKey] : NO;
    }
    return self;
}

#pragma mark - 开关控制

- (BOOL)isCaptureEnabled {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    return [[DatabaseManager sharedManager] getSwitch:@"uc_applog_capture" bundleID:bundleID defaultValue:NO];
}

- (void)startCaptureIfEnabled {
    if (self.isCapturing) return;
    if (![self isCaptureEnabled]) return;
    [self startCapture];
}

- (void)startCapture {
    if (self.isCapturing) return;
    self.isCapturing = YES;

    // 方案1：hook NSLogv，轻量，主线程只做入队
    if (self.captureNSLog) {
        [self hookNSLog];
    }

    // 方案2：OSLog 私有 SPI，较耗性能，默认关闭
    if (self.captureOSLog) {
        [self startOSLogCapture];
    }

    // 定时 flush 和清理
    [self startFlushTimer];
    [self startCleanupTimer];
}

- (void)stopCapture {
    self.isCapturing = NO;
    [self flushLogs];
    [self.flushTimer invalidate];
    self.flushTimer = nil;
    [self.cleanupTimer invalidate];
    self.cleanupTimer = nil;
}

#pragma mark - 批量写入

- (void)enqueueLog:(NSString *)msg {
    if (!msg || msg.length == 0) return;
    dispatch_async(self.logQueue, ^{
        [self.pendingLogs addObject:msg];
        if (self.pendingLogs.count >= 30) {
            [self flushLogs];
        }
    });
}

- (void)flushLogs {
    dispatch_async(self.logQueue, ^{
        if (self.pendingLogs.count == 0) return;
        NSArray<NSString *> *batch = [self.pendingLogs copy];
        [self.pendingLogs removeAllObjects];
        DatabaseManager *db = [DatabaseManager sharedManager];
        for (NSString *msg in batch) {
            [db insertLogText:msg];
        }
    });
}

- (void)startFlushTimer {
    [self flushLogs];
    self.flushTimer = [NSTimer scheduledTimerWithTimeInterval:2.0
                                                         target:self
                                                       selector:@selector(flushLogs)
                                                       userInfo:nil
                                                        repeats:YES];
}

#pragma mark - NSLog Hook

- (void)hookNSLog {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding rebind = {"NSLogv", (void *)uc_NSLogv, (void **)&orig_NSLogv};
        flex_rebind_symbols(&rebind, 1);
    });
}

#pragma mark - OSLog 捕获

- (void)startOSLogCapture {
    if (self.osLogController) return;
    __weak typeof(self) weakSelf = self;
    FLEXOSLogController *controller = [FLEXOSLogController withUpdateHandler:^(NSArray<FLEXSystemLogMessage *> *newMessages) {
        for (FLEXSystemLogMessage *msg in newMessages) {
            NSString *text = msg.messageText;
            if (text.length > 0) {
                [weakSelf enqueueLog:text];
            }
        }
    }];
    controller.persistent = YES;
    [controller startMonitoring];
    self.osLogController = controller;
}

#pragma mark - 查询/删除

- (NSArray<NSDictionary *> *)allLogs {
    [self flushLogs];
    return [[DatabaseManager sharedManager] queryLogRecords:self.maxLogCount];
}

- (NSArray<NSDictionary *> *)logsWithLimit:(NSInteger)limit {
    [self flushLogs];
    return [[DatabaseManager sharedManager] queryLogRecords:limit];
}

- (void)deleteLogById:(NSInteger)logId {
    [[DatabaseManager sharedManager] deleteLogById:logId];
}

- (void)clearAllLogs {
    [self flushLogs];
    [[DatabaseManager sharedManager] clearTable:@"yunxingrizhi"];
}

#pragma mark - 清理策略

- (void)startCleanupTimer {
    [self cleanupIfNeeded];
    self.cleanupTimer = [NSTimer scheduledTimerWithTimeInterval:300.0
                                                           target:self
                                                         selector:@selector(cleanupIfNeeded)
                                                         userInfo:nil
                                                          repeats:YES];
}

- (void)cleanupIfNeeded {
    if (!self.isCaptureEnabled) return;
    DatabaseManager *db = [DatabaseManager sharedManager];
    if (self.maxLogDays > 0) {
        [db cleanupLogsOlderThanDays:self.maxLogDays];
    }
    if (self.maxLogCount > 0) {
        [db cleanupLogsMaxCount:self.maxLogCount];
    }
}

#pragma mark - 导出

- (void)exportAllLogsFromViewController:(UIViewController *)vc completion:(void (^)(BOOL))completion {
    // 导出时使用大 limit，不限制为 maxLogCount（后者是 UI 展示的保留策略数）
    NSArray<NSDictionary *> *logs = [self logsWithLimit:99999];
    if (logs.count == 0) {
        if (completion) completion(NO);
        return;
    }
    [UCExportManager exportItems:logs tableName:@"yunxingrizhi" fromViewController:vc completion:completion];
}

- (void)exportLogRecord:(NSDictionary *)record fromViewController:(UIViewController *)vc completion:(void (^)(BOOL))completion {
    if (!record) {
        if (completion) completion(NO);
        return;
    }
    [UCExportManager exportItems:@[record] tableName:@"yunxingrizhi_single" fromViewController:vc completion:completion];
}

#pragma mark - 设置持久化

- (void)setMaxLogCount:(NSInteger)maxLogCount {
    _maxLogCount = maxLogCount;
    [[NSUserDefaults standardUserDefaults] setInteger:maxLogCount forKey:kUCAppLogMaxCountKey];
}

- (void)setMaxLogDays:(NSInteger)maxLogDays {
    _maxLogDays = maxLogDays;
    [[NSUserDefaults standardUserDefaults] setInteger:maxLogDays forKey:kUCAppLogMaxDaysKey];
}

- (void)setCaptureNSLog:(BOOL)captureNSLog {
    _captureNSLog = captureNSLog;
    [[NSUserDefaults standardUserDefaults] setBool:captureNSLog forKey:kUCAppLogCaptureNSLogKey];
}

- (void)setCaptureOSLog:(BOOL)captureOSLog {
    _captureOSLog = captureOSLog;
    [[NSUserDefaults standardUserDefaults] setBool:captureOSLog forKey:kUCAppLogCaptureOSLogKey];
}

@end
