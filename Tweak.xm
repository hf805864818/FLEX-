/**
 * FLEX++ - 独立注入版
 * 双击状态栏激活FLEX++调试工具
 * 版本号由 GitHub Actions 自动更新
 */

#import <UIKit/UIKit.h>
#import "FLEX/FLEX.h"

%hook UIStatusBarManager

- (void)handleStatusBarTapWithEvent:(UIEvent *)event {
    %orig;
    
    static NSTimeInterval lastTapTime = 0;
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    
    if (now - lastTapTime < 0.5) {
        // 双击状态栏 → 切换FLEX++
        [[FLEXManager sharedManager] toggleExplorer];
    }
    
    lastTapTime = now;
}

%end

%ctor {
    %init;
    
    // 延时加载，确保UI初始化完成后再显示
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[FLEXManager sharedManager] showExplorer];
    });
}
