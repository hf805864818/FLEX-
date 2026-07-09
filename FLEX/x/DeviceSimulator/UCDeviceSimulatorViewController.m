//
//  UCDeviceSimulatorViewController.m
//  FLEX
//
//  设备模拟器 UI 面板 - 设置伪造的系统版本和App版本
//

#import "UCDeviceSimulatorViewController.h"
#import "UCDeviceSimulator.h"
#import "FLEXColor.h"

@interface UCDeviceSimulatorViewController () <UITextFieldDelegate>

@property (nonatomic, strong) UITextField *systemVersionField;
@property (nonatomic, strong) UITextField *appVersionField;
@property (nonatomic, strong) UILabel *modeLabel;

@end

@implementation UCDeviceSimulatorViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.title = @"设备模拟器";
    self.view.backgroundColor = [FLEXColor groupedBackgroundColor];

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemDone
        target:self action:@selector(dismissPanel)];

    [self buildUI];
    [self refreshUI];
}

- (void)buildUI {
    CGFloat padding = 16;
    CGFloat y = padding + 80;

    // 模式标签
    self.modeLabel = [[UILabel alloc] initWithFrame:CGRectMake(padding, y, self.view.bounds.size.width - padding * 2, 20)];
    self.modeLabel.font = [UIFont systemFontOfSize:14];
    self.modeLabel.textColor = [FLEXColor deemphasizedTextColor];
    self.modeLabel.text = [NSString stringWithFormat:@"当前设备模式: %@", [UCDeviceSimulator sharedInstance].currentModeText];
    [self.view addSubview:self.modeLabel];
    y += 30;

    // 提示文字
    UILabel *hintLabel = [[UILabel alloc] initWithFrame:CGRectMake(padding, y, self.view.bounds.size.width - padding * 2, 16)];
    hintLabel.font = [UIFont systemFontOfSize:12];
    hintLabel.textColor = [FLEXColor deemphasizedTextColor];
    hintLabel.text = @"保存后立即对常用系统接口生效。";
    [self.view addSubview:hintLabel];
    y += 28;

    // 白色输入卡片
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(padding, y, self.view.bounds.size.width - padding * 2, 88)];
    card.backgroundColor = [FLEXColor primaryBackgroundColor];
    card.layer.cornerRadius = 10;
    [self.view addSubview:card];

    // 系统版本
    self.systemVersionField = [[UITextField alloc] initWithFrame:CGRectMake(12, 0, card.bounds.size.width - 24, 44)];
    self.systemVersionField.placeholder = @"系统版本 (如 17.0)";
    self.systemVersionField.font = [UIFont systemFontOfSize:16];
    self.systemVersionField.keyboardType = UIKeyboardTypeDecimalPad;
    self.systemVersionField.returnKeyType = UIReturnKeyNext;
    self.systemVersionField.delegate = self;
    [card addSubview:self.systemVersionField];

    // 分割线
    UIView *divider = [[UIView alloc] initWithFrame:CGRectMake(12, 44, card.bounds.size.width - 24, 0.5)];
    divider.backgroundColor = [UIColor colorWithWhite:0.85 alpha:1];
    [card addSubview:divider];

    // App版本
    self.appVersionField = [[UITextField alloc] initWithFrame:CGRectMake(12, 44, card.bounds.size.width - 24, 44)];
    self.appVersionField.placeholder = @"App版本 (如 2.0.19)";
    self.appVersionField.font = [UIFont systemFontOfSize:16];
    self.appVersionField.keyboardType = UIKeyboardTypeDecimalPad;
    self.appVersionField.returnKeyType = UIReturnKeyDone;
    self.appVersionField.delegate = self;
    [card addSubview:self.appVersionField];

    y += 108;

    // 按钮区
    CGFloat btnWidth = (self.view.bounds.size.width - padding * 2 - 12) / 2;
    CGFloat btnHeight = 44;

    // 保存为 iPhone
    UIButton *iphoneBtn = [self makeButtonWithTitle:@"保存为 iPhone" color:[FLEXColor tintColor]];
    iphoneBtn.frame = CGRectMake(padding, y, btnWidth, btnHeight);
    [iphoneBtn addTarget:self action:@selector(saveAsiPhone) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:iphoneBtn];

    // 保存为 iPad
    UIButton *ipadBtn = [self makeButtonWithTitle:@"保存为 iPad" color:[FLEXColor tintColor]];
    ipadBtn.frame = CGRectMake(padding + btnWidth + 12, y, btnWidth, btnHeight);
    [ipadBtn addTarget:self action:@selector(saveAsiPad) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:ipadBtn];

    y += btnHeight + 12;

    // 恢复真实信息
    UIButton *restoreBtn = [self makeButtonWithTitle:@"恢复真实信息" color:[FLEXColor destructiveColor]];
    restoreBtn.frame = CGRectMake(padding, y, btnWidth, btnHeight);
    [restoreBtn addTarget:self action:@selector(restoreRealInfo) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:restoreBtn];

    // 取消
    UIButton *cancelBtn = [self makeButtonWithTitle:@"取消" color:[FLEXColor iconColor]];
    cancelBtn.frame = CGRectMake(padding + btnWidth + 12, y, btnWidth, btnHeight);
    [cancelBtn addTarget:self action:@selector(dismissPanel) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:cancelBtn];
}

- (UIButton *)makeButtonWithTitle:(NSString *)title color:(UIColor *)color {
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [btn setTitle:title forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightMedium];
    btn.backgroundColor = [FLEXColor secondaryBackgroundColor];
    btn.layer.cornerRadius = 10;
    btn.tintColor = color;
    return btn;
}

- (void)refreshUI {
    UCDeviceSimulator *sim = [UCDeviceSimulator sharedInstance];
    self.systemVersionField.text = sim.isSimulating ? sim.simulatedSystemVersion : @"";
    self.appVersionField.text = sim.isSimulating ? sim.simulatedAppVersion : @"";

    NSString *mode = [sim.currentModeText isEqualToString:@"真实设备"] ? @"真实设备" : [NSString stringWithFormat:@"%@模拟", sim.currentModeText];
    self.modeLabel.text = [NSString stringWithFormat:@"当前设备模式: %@", mode];
}

#pragma mark - Actions

- (void)saveAsiPhone {
    [self applySettings];
    [[UCDeviceSimulator sharedInstance] saveAsiPhone];
    [self refreshUI];
    [self showToast:@"已保存为 iPhone"];
}

- (void)saveAsiPad {
    [self applySettings];
    [[UCDeviceSimulator sharedInstance] saveAsiPad];
    [self refreshUI];
    [self showToast:@"已保存为 iPad"];
}

- (void)restoreRealInfo {
    [[UCDeviceSimulator sharedInstance] restoreRealInfo];
    [self refreshUI];
    [self showToast:@"已恢复真实设备信息"];
}

- (void)applySettings {
    UCDeviceSimulator *sim = [UCDeviceSimulator sharedInstance];
    sim.simulatedSystemVersion = self.systemVersionField.text.length > 0 ? self.systemVersionField.text : @"17.0";
    sim.simulatedAppVersion = self.appVersionField.text.length > 0 ? self.appVersionField.text : @"";
    [sim enableSimulation];
}

- (void)dismissPanel {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)showToast:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil message:message preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [alert dismissViewControllerAnimated:YES completion:nil];
    });
}

#pragma mark - UITextFieldDelegate

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if (textField == self.systemVersionField) {
        [self.appVersionField becomeFirstResponder];
    } else {
        [textField resignFirstResponder];
    }
    return YES;
}

- (void)textFieldDidEndEditing:(UITextField *)textField {
    [self applySettings];
    [self refreshUI];
}

@end
