/**
 * FLEX++ - 独立注入版
 * 双击状态栏激活FLEX++调试工具
 * 版本号由 GitHub Actions 自动更新
 */

#import <UIKit/UIKit.h>
#import "FLEX/FLEX.h"
#import "FLEX/x/SocketCapture/UCSocketCaptureManager.h"
#import "FLEX/x/MemoryScan/UCMemoryScanManager.h"
#import "FLEX/x/Decrypt/UCDecryptTool.h"
#import "FLEX/x/UCLog/UCAppLogManager.h"

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
        
        // ★ 激活Socket层Hook（捕获dart:io请求）
        [[UCSocketCaptureManager sharedManager] installHooks];
        NSLog(@"[FLEX++] SocketCapture 模块已启动");
        
        // ★ 启动内存扫描（扫描libapp.so找硬编码密钥）
        [[UCMemoryScanManager sharedManager] startScan];
        NSLog(@"[FLEX++] MemoryScan 模块已启动");
        
        // ★ 按开关启动日志捕获（默认关闭，避免卡顿）
        [[UCAppLogManager sharedManager] startCaptureIfEnabled];
    });
}
