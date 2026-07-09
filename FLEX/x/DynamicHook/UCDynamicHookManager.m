#import "UCDynamicHookManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <objc/runtime.h>

static void recordHook(NSString *hookType, NSString *className, NSString *methodName, NSString *extra) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@ %@%@%@",
                      hookType, className ?: @"?", methodName ?: @"?",
                      extra ? @" | " : @"", extra ?: @""];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"dynamic_hook"
                                                bundleID:bundleID
                                                    text:text];
}

@implementation UCDynamicHookManager

+ (instancetype)sharedManager {
    static UCDynamicHookManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCDynamicHookManager alloc] init];
    });
    return instance;
}

static void hookNSURLConnection_sendSync(Class cls) {
    SEL sel = @selector(sendSynchronousRequest:returningResponse:error:);
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(id self, NSURLRequest *req, NSURLResponse **resp, NSError **err) {
        recordHook(@"OC方法", @"NSURLConnection", @"sendSynchronousRequest:returningResponse:error:", nil);
        NSData *(*origFunc)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **) = (void *)orig;
        return origFunc(self, sel, req, resp, err);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSURLConnection_sendAsync(Class cls) {
    SEL sel = @selector(sendAsynchronousRequest:queue:completionHandler:);
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(id self, NSURLRequest *req, NSOperationQueue *queue, void (^handler)(NSURLResponse *, NSData *, NSError *)) {
        recordHook(@"OC方法", @"NSURLConnection", @"sendAsynchronousRequest:queue:completionHandler:", nil);
        void (*origFunc)(id, SEL, NSURLRequest *, NSOperationQueue *, void (^)(NSURLResponse *, NSData *, NSError *)) = (void *)orig;
        origFunc(self, sel, req, queue, handler);
    });
    if (replacement) method_setImplementation(m, replacement);
}

// ─── NSURLSession ───

static void hookNSURLSession_dataTaskRequest(Class cls) {
    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSURLSession *self, NSURLRequest *req, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
        recordHook(@"OC方法", @"NSURLSession", @"dataTaskWithRequest:completionHandler:", nil);
        NSURLSessionDataTask *(*origFunc)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = (void *)orig;
        return origFunc(self, sel, req, handler);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSURLSession_dataTaskURL(Class cls) {
    SEL sel = @selector(dataTaskWithURL:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSURLSession *self, NSURL *url, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
        recordHook(@"OC方法", @"NSURLSession", @"dataTaskWithURL:completionHandler:", nil);
        NSURLSessionDataTask *(*origFunc)(id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *)) = (void *)orig;
        return origFunc(self, sel, url, handler);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSURLSession_downloadTask(Class cls) {
    SEL sel = @selector(downloadTaskWithRequest:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSURLSession *self, NSURLRequest *req, void (^handler)(NSURL *, NSURLResponse *, NSError *)) {
        recordHook(@"OC方法", @"NSURLSession", @"downloadTaskWithRequest:completionHandler:", nil);
        NSURLSessionDownloadTask *(*origFunc)(id, SEL, NSURLRequest *, void (^)(NSURL *, NSURLResponse *, NSError *)) = (void *)orig;
        return origFunc(self, sel, req, handler);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSURLSession_uploadTask(Class cls) {
    SEL sel = @selector(uploadTaskWithRequest:fromData:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSURLSession *self, NSURLRequest *req, NSData *bodyData, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
        recordHook(@"OC方法", @"NSURLSession", @"uploadTaskWithRequest:fromData:completionHandler:", nil);
        NSURLSessionUploadTask *(*origFunc)(id, SEL, NSURLRequest *, NSData *, void (^)(NSData *, NSURLResponse *, NSError *)) = (void *)orig;
        return origFunc(self, sel, req, bodyData, handler);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSFileManager_createFile(Class cls) {
    SEL sel = @selector(createFileAtPath:contents:attributes:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSFileManager *self, NSString *path, NSData *data, NSDictionary *attr) {
        recordHook(@"OC方法", @"NSFileManager", @"createFileAtPath:contents:attributes:", [NSString stringWithFormat:@"path=%@", path]);
        BOOL (*origFunc)(id, SEL, NSString *, NSData *, NSDictionary *) = (void *)orig;
        return origFunc(self, sel, path, data, attr);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSFileManager_copyItem(Class cls) {
    SEL sel = @selector(copyItemAtPath:toPath:error:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSFileManager *self, NSString *src, NSString *dst, NSError **err) {
        recordHook(@"OC方法", @"NSFileManager", @"copyItemAtPath:toPath:error:", [NSString stringWithFormat:@"%@ -> %@", src, dst]);
        BOOL (*origFunc)(id, SEL, NSString *, NSString *, NSError **) = (void *)orig;
        return origFunc(self, sel, src, dst, err);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookNSFileManager_moveItem(Class cls) {
    SEL sel = @selector(moveItemAtPath:toPath:error:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(NSFileManager *self, NSString *src, NSString *dst, NSError **err) {
        recordHook(@"OC方法", @"NSFileManager", @"moveItemAtPath:toPath:error:", [NSString stringWithFormat:@"%@ -> %@", src, dst]);
        BOOL (*origFunc)(id, SEL, NSString *, NSString *, NSError **) = (void *)orig;
        return origFunc(self, sel, src, dst, err);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookFMDatabase_executeUpdate(Class cls) {
    SEL sel = @selector(executeUpdate:withArgumentsInArray:orDictionary:orVAList:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(id self, NSString *sql, NSArray *args, NSDictionary *dict, va_list list) {
        recordHook(@"OC方法", @"FMDatabase", @"executeUpdate:", [NSString stringWithFormat:@"sql=%@", sql ? [sql substringToIndex:MIN(sql.length, 80)] : @"?"]);
        BOOL (*origFunc)(id, SEL, NSString *, NSArray *, NSDictionary *, va_list) = (void *)orig;
        return origFunc(self, sel, sql, args, dict, list);
    });
    if (replacement) method_setImplementation(m, replacement);
}

static void hookFMDatabase_executeQuery(Class cls) {
    SEL sel = @selector(executeQuery:withArgumentsInArray:orDictionary:orVAList:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    IMP replacement = imp_implementationWithBlock(^(id self, NSString *sql, NSArray *args, NSDictionary *dict, va_list list) {
        recordHook(@"OC方法", @"FMDatabase", @"executeQuery:", [NSString stringWithFormat:@"sql=%@", sql ? [sql substringToIndex:MIN(sql.length, 80)] : @"?"]);
        id (*origFunc)(id, SEL, NSString *, NSArray *, NSDictionary *, va_list) = (void *)orig;
        return origFunc(self, sel, sql, args, dict, list);
    });
    if (replacement) method_setImplementation(m, replacement);
}

// ─── installHooks ───

- (void)installHooks {
    Class connClass = NSClassFromString(@"NSURLConnection");
    if (connClass) {
        hookNSURLConnection_sendSync(connClass);
        hookNSURLConnection_sendAsync(connClass);
    }

    Class sessionClass = NSClassFromString(@"NSURLSession");
    if (sessionClass) {
        hookNSURLSession_dataTaskRequest(sessionClass);
        hookNSURLSession_dataTaskURL(sessionClass);
        hookNSURLSession_downloadTask(sessionClass);
        hookNSURLSession_uploadTask(sessionClass);
    }

    Class fmClass = NSClassFromString(@"NSFileManager");
    if (fmClass) {
        hookNSFileManager_createFile(fmClass);
        hookNSFileManager_copyItem(fmClass);
        hookNSFileManager_moveItem(fmClass);
    }

    Class dbClass = NSClassFromString(@"FMDatabase");
    if (dbClass) {
        hookFMDatabase_executeUpdate(dbClass);
        hookFMDatabase_executeQuery(dbClass);
    }

    NSLog(@"[DynamicHook] 动态Hook模块已安装 (12 methods)");
}

@end
