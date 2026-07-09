#import "UCDynamicHookManager.h"
#import "../Decrypt/DatabaseManager.h"
#import <substrate.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static void recordHook(NSString *hookType, NSString *className, NSString *methodName, NSString *extra) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSString *text = [NSString stringWithFormat:@"[%@] %@ %@%@%@",
                      hookType, className ?: @"?", methodName ?: @"?",
                      extra ? @" | " : @"", extra ?: @""];
    [[DatabaseManager sharedManager] insertDataIntoTable:@"dynamic_hook"
                                                bundleID:bundleID
                                                    text:text];
}

static void dynamicHookCallback(NSString *className, NSString *methodName, NSString *hookType) {
    recordHook(hookType, className, methodName, @"运行时代码Hook");
}

@interface UCDynamicHookManager ()
@property (nonatomic, strong) NSMutableArray<NSString *> *hookedMethods;
@end

@implementation UCDynamicHookManager

+ (instancetype)sharedManager {
    static UCDynamicHookManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCDynamicHookManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _hookedMethods = [NSMutableArray array];
    }
    return self;
}

static void installMethodHook(Class cls, SEL sel, NSString *hookType) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        m = class_getClassMethod(cls, sel);
        if (!m) return;
    }

    NSString *className = NSStringFromClass(cls);
    NSString *methodName = NSStringFromSelector(sel);

    IMP originalIMP = method_getImplementation(m);
    const char *typeEncoding = method_getTypeEncoding(m);

    IMP newIMP = imp_implementationWithBlock(^(__unsafe_unretained id self, ...) {
        recordHook(hookType, className, methodName, @"已被拦截");
        // 无法直接调用可变参数的原始IMP，这里只做记录
        return;
    });

    if (class_addMethod(cls, sel, newIMP, typeEncoding)) {
        recordHook(hookType, className, methodName, @"新增Hook");
    } else {
        method_setImplementation(m, newIMP);
        recordHook(hookType, className, methodName, @"替换Hook");
    }
}

- (void)installHooks {
    // Hook NSURLConnection
    Class connClass = NSClassFromString(@"NSURLConnection");
    if (connClass) {
        installMethodHook(connClass, NSSelectorFromString(@"sendSynchronousRequest:returningResponse:error:"), @"OC方法");
        installMethodHook(connClass, NSSelectorFromString(@"sendAsynchronousRequest:queue:completionHandler:"), @"OC方法");
    }

    // Hook NSURLSession
    Class sessionClass = NSClassFromString(@"NSURLSession");
    if (sessionClass) {
        installMethodHook(sessionClass, NSSelectorFromString(@"dataTaskWithRequest:completionHandler:"), @"OC方法");
        installMethodHook(sessionClass, NSSelectorFromString(@"dataTaskWithURL:completionHandler:"), @"OC方法");
        installMethodHook(sessionClass, NSSelectorFromString(@"downloadTaskWithRequest:completionHandler:"), @"OC方法");
        installMethodHook(sessionClass, NSSelectorFromString(@"uploadTaskWithRequest:fromData:completionHandler:"), @"OC方法");
    }

    // Hook NSFileManager - 文件写入
    Class fmClass = NSClassFromString(@"NSFileManager");
    if (fmClass) {
        installMethodHook(fmClass, NSSelectorFromString(@"createFileAtPath:contents:attributes:"), @"OC方法");
        installMethodHook(fmClass, NSSelectorFromString(@"copyItemAtPath:toPath:error:"), @"OC方法");
        installMethodHook(fmClass, NSSelectorFromString(@"moveItemAtPath:toPath:error:"), @"OC方法");
    }

    // Hook 数据库操作
    Class mmClass = NSClassFromString(@"FMDatabase");
    if (mmClass) {
        installMethodHook(mmClass, NSSelectorFromString(@"executeUpdate:withArgumentsInArray:orDictionary:orVAList:"), @"OC方法");
        installMethodHook(mmClass, NSSelectorFromString(@"executeQuery:withArgumentsInArray:orDictionary:orVAList:"), @"OC方法");
    }

    NSLog(@"[DynamicHook] 动态Hook模块已安装");
}

@end
