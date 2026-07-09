//
//  UCDeviceSimulator.m
//  FLEX
//
//  设备模拟器 - 通过Method Swizzling拦截 UIDevice / NSBundle 返回值
//

#import "UCDeviceSimulator.h"
#import "UCDeviceSimulatorViewController.h"
#import "FLEXNavigationController.h"
#import <objc/runtime.h>

#pragma mark - Swizzled UIDevice Methods

static NSString * (*original_device_model)(id self, SEL _cmd);
static NSString * (*original_device_systemVersion)(id self, SEL _cmd);
static UIUserInterfaceIdiom (*original_device_userInterfaceIdiom)(id self, SEL _cmd);

static NSString * swizzled_model(id self, SEL _cmd) {
    UCDeviceSimulator *sim = [UCDeviceSimulator sharedInstance];
    if (sim.isSimulating) {
        return (sim.simulatedIdiom == UIUserInterfaceIdiomPad) ? @"iPad" : @"iPhone";
    }
    return original_device_model(self, _cmd);
}

static NSString * swizzled_systemVersion(id self, SEL _cmd) {
    UCDeviceSimulator *sim = [UCDeviceSimulator sharedInstance];
    if (sim.isSimulating && sim.simulatedSystemVersion.length > 0) {
        return sim.simulatedSystemVersion;
    }
    return original_device_systemVersion(self, _cmd);
}

static UIUserInterfaceIdiom swizzled_userInterfaceIdiom(id self, SEL _cmd) {
    UCDeviceSimulator *sim = [UCDeviceSimulator sharedInstance];
    if (sim.isSimulating) {
        return sim.simulatedIdiom;
    }
    return original_device_userInterfaceIdiom(self, _cmd);
}

#pragma mark - Swizzled NSBundle Methods

static NSDictionary * (*original_bundle_infoDictionary)(id self, SEL _cmd);

static NSDictionary * swizzled_infoDictionary(id self, SEL _cmd) {
    NSDictionary *dict = original_bundle_infoDictionary(self, _cmd);
    UCDeviceSimulator *sim = [UCDeviceSimulator sharedInstance];
    if (sim.isSimulating && sim.simulatedAppVersion.length > 0) {
        NSMutableDictionary *mutable = [dict mutableCopy];
        mutable[@"CFBundleShortVersionString"] = sim.simulatedAppVersion;
        mutable[@"CFBundleVersion"] = sim.simulatedAppVersion;
        return [mutable copy];
    }
    return dict;
}

#pragma mark - UCDeviceSimulator

@implementation UCDeviceSimulator

+ (instancetype)sharedInstance {
    static UCDeviceSimulator *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[UCDeviceSimulator alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isSimulating = NO;
        _simulatedSystemVersion = @"17.0";
        _simulatedAppVersion = @"";
        _simulatedIdiom = UIUserInterfaceIdiomPhone;
        [self installSwizzles];
    }
    return self;
}

- (NSString *)currentModeText {
    if (!self.isSimulating) {
        return @"真实设备";
    }
    return (self.simulatedIdiom == UIUserInterfaceIdiomPad) ? @"iPad" : @"iPhone";
}

#pragma mark - Method Swizzling

- (void)installSwizzles {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // UIDevice - model
        Method m1 = class_getInstanceMethod([UIDevice class], @selector(model));
        original_device_model = (void *)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)swizzled_model);

        // UIDevice - systemVersion
        Method m2 = class_getInstanceMethod([UIDevice class], @selector(systemVersion));
        original_device_systemVersion = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)swizzled_systemVersion);

        // UIDevice - userInterfaceIdiom
        Method m3 = class_getInstanceMethod([UIDevice class], @selector(userInterfaceIdiom));
        original_device_userInterfaceIdiom = (void *)method_getImplementation(m3);
        method_setImplementation(m3, (IMP)swizzled_userInterfaceIdiom);

        // NSBundle - infoDictionary
        Method m4 = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
        original_bundle_infoDictionary = (void *)method_getImplementation(m4);
        method_setImplementation(m4, (IMP)swizzled_infoDictionary);
    });
}

#pragma mark - Actions

- (void)enableSimulation {
    _isSimulating = YES;
}

- (void)disableSimulation {
    _isSimulating = NO;
}

- (void)saveAsiPhone {
    _simulatedModel = @"iPhone";
    _simulatedIdiom = UIUserInterfaceIdiomPhone;
    _isSimulating = YES;
}

- (void)saveAsiPad {
    _simulatedModel = @"iPad";
    _simulatedIdiom = UIUserInterfaceIdiomPad;
    _isSimulating = YES;
}

- (void)restoreRealInfo {
    _isSimulating = NO;
    _simulatedSystemVersion = @"";
    _simulatedAppVersion = @"";
    _simulatedIdiom = [[UIDevice currentDevice] userInterfaceIdiom];
}

#pragma mark - Panel Presentation

+ (void)presentSimulatorPanelFromViewController:(UIViewController *)presentingVC {
    UCDeviceSimulatorViewController *vc = [[UCDeviceSimulatorViewController alloc] init];
    FLEXNavigationController *nav = [[FLEXNavigationController alloc] initWithRootViewController:vc];
    [presentingVC presentViewController:nav animated:YES completion:nil];
}

@end
