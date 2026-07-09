//
//  UCDeviceSimulator.h
//  FLEX
//
//  设备模拟器 - 伪造设备型号/iOS版本/App版本等系统信息
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface UCDeviceSimulator : NSObject

+ (instancetype)sharedInstance;

/// 是否正在模拟设备信息
@property (nonatomic, assign, readonly) BOOL isSimulating;

/// 模拟的系统版本号 (如 "17.0")
@property (nonatomic, copy) NSString *simulatedSystemVersion;

/// 模拟的App版本号 (如 "2.0.19")
@property (nonatomic, copy) NSString *simulatedAppVersion;

/// 当前设备模式描述
@property (nonatomic, copy, readonly) NSString *currentModeText;

/// 开始模拟（启用Method Swizzling）
- (void)enableSimulation;

/// 停止模拟（恢复真实信息）
- (void)disableSimulation;

/// 预设为iPhone (model=iPhone, idiom=Phone)
- (void)saveAsiPhone;

/// 预设为iPad (model=iPad, idiom=Pad)
- (void)saveAsiPad;

/// 恢复真实设备信息并关闭模拟
- (void)restoreRealInfo;

/// 显示设备模拟器面板
+ (void)presentSimulatorPanelFromViewController:(UIViewController *)presentingVC;

@end

NS_ASSUME_NONNULL_END
