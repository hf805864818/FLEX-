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
        [[DatabaseManager sharedManager] insertLogText:msg];
    }
}

@interface UCAppLogManager ()
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
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        _maxLogCount = [ud integerForKey:kUCAppLogMaxCountKey];
        if (_maxLogCount <= 0) _maxLogCount = 5000;
        _maxLogDays = [ud integerForKey:kUCAppLogMaxDaysKey];
        if (_maxLogDays <= 0) _maxLogDays = 7;
        _captureNSLog = [ud objectForKey:kUCAppLogCaptureNSLogKey] ? [ud boolForKey:kUCAppLogCaptureNSLogKey] : YES;
        _captureOSLog = [ud objectForKey:kUCAppLogCaptureOSLogKey] ? [ud boolForKey:kUCAppLogCaptureOSLogKey] : YES;
    }
    return self;
}

- (void)startCapture {
    if (self.isCapturing) return;
    self.isCapturing = YES;

    // 方案1：重定向 stderr，捕获 NSLog / print
    if (self.captureNSLog) {
        [self redirectStderrToFile];
    }

    // 方案2：hook NSLogv（更直接，不依赖文件重定向）
    if (self.captureNSLog) {
        [self hookNSLog];
    }

    // 方案3：OSLog 私有 SPI，捕获 os_log / 系统日志
    if (self.captureOSLog) {
        [self startOSLogCapture];
    }

    // 定时清理
    [self startCleanupTimer];
}

- (void)stopCapture {
    self.isCapturing = NO;
    [self.cleanupTimer invalidate];
    self.cleanupTimer = nil;
}

#pragma mark - stderr 重定向

- (void)redirectStderrToFile {
    NSString *logPath = [self logFilePath];
    const char *path = [logPath UTF8String];
    freopen(path, "a+", stderr);
}

- (NSString *)logFilePath {
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [doc stringByAppendingPathComponent:@"uc_applog_stderr.log"];
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
                [[DatabaseManager sharedManager] insertLogText:text];
            }
        }
        [weakSelf cleanupIfNeeded];
    }];
    controller.persistent = YES;
    [controller startMonitoring];
    self.osLogController = controller;
}

#pragma mark - 查询/删除

- (NSArray<NSDictionary *> *)allLogs {
    return [[DatabaseManager sharedManager] queryLogRecords:self.maxLogCount];
}

- (NSArray<NSDictionary *> *)logsWithLimit:(NSInteger)limit {
    return [[DatabaseManager sharedManager] queryLogRecords:limit];
}

- (void)deleteLogById:(NSInteger)logId {
    [[DatabaseManager sharedManager] deleteLogById:logId];
}

- (void)clearAllLogs {
    [[DatabaseManager sharedManager] clearTable:@"yunxingrizhi"];
    // 同时清空 stderr 重定向文件
    [[NSFileManager defaultManager] removeItemAtPath:[self logFilePath] error:nil];
}

#pragma mark - 清理策略

- (void)startCleanupTimer {
    [self cleanupIfNeeded];
    self.cleanupTimer = [NSTimer scheduledTimerWithTimeInterval:60.0
                                                           target:self
                                                         selector:@selector(cleanupIfNeeded)
                                                         userInfo:nil
                                                          repeats:YES];
}

- (void)cleanupIfNeeded {
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
    NSArray<NSDictionary *> *logs = [self allLogs];
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
