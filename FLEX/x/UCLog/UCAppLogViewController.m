#import "UCAppLogViewController.h"
#import "UCAppLogManager.h"
#import "../Decrypt/DatabaseManager.h"
#import "../Decrypt/UCExportManager.h"

static NSString * const kCellIdentifier = @"UCAppLogCell";

@interface UCAppLogViewController () <UITableViewDataSource, UITableViewDelegate, UISearchResultsUpdating>

@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *logs;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *filteredLogs;
@property (nonatomic, strong) UISearchController *searchController;
@property (nonatomic, strong) NSTimer *refreshTimer;
@property (nonatomic, assign) BOOL isExporting;

@end

@implementation UCAppLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"运行日志";
    self.logs = [NSMutableArray array];
    self.filteredLogs = [NSMutableArray array];
    self.view.backgroundColor = [UIColor blackColor];

    [self setupSearchController];
    [self setupTableView];
    [self setupToolbar];
    [self setupNavigationBar];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if (![[UCAppLogManager sharedManager] isCaptureEnabled]) {
        [self showToast:@"日志捕获已关闭，请在功能开关中开启"];
    } else {
        [[UCAppLogManager sharedManager] startCaptureIfEnabled];
    }
    [self reloadData];
    [self startRefreshTimer];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self.refreshTimer invalidate];
    self.refreshTimer = nil;
}

#pragma mark - UI Setup

- (void)setupSearchController {
    self.searchController = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searchController.searchResultsUpdater = self;
    self.searchController.obscuresBackgroundDuringPresentation = NO;
    self.searchController.searchBar.placeholder = @"搜索日志";
    self.searchController.searchBar.barStyle = UIBarStyleBlack;
    self.navigationItem.searchController = self.searchController;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
}

- (void)setupTableView {
    self.tableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStylePlain];
    self.tableView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.tableView.backgroundColor = [UIColor blackColor];
    self.tableView.separatorColor = [UIColor darkGrayColor];
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    [self.tableView registerClass:[UITableViewCell class] forCellReuseIdentifier:kCellIdentifier];
    [self.view addSubview:self.tableView];
}

- (void)setupToolbar {
    UIBarButtonItem *exportAll = [[UIBarButtonItem alloc] initWithTitle:@"导出全部"
                                                                   style:UIBarButtonItemStylePlain
                                                                  target:self
                                                                  action:@selector(exportAllTapped:)];
    UIBarButtonItem *clearAll = [[UIBarButtonItem alloc] initWithTitle:@"清除全部"
                                                                  style:UIBarButtonItemStylePlain
                                                                 target:self
                                                                 action:@selector(clearAllTapped:)];
    UIBarButtonItem *settings = [[UIBarButtonItem alloc] initWithTitle:@"设置"
                                                                  style:UIBarButtonItemStylePlain
                                                                 target:self
                                                                 action:@selector(settingsTapped:)];
    UIBarButtonItem *flexSpace = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                                                target:nil
                                                                                action:nil];

    self.toolbarItems = @[exportAll, flexSpace, clearAll, flexSpace, settings];
    self.navigationController.toolbar.barStyle = UIBarStyleBlack;
    self.navigationController.toolbarHidden = NO;
}

- (void)setupNavigationBar {
    UIBarButtonItem *refresh = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                                               target:self
                                                                               action:@selector(reloadData)];
    self.navigationItem.rightBarButtonItem = refresh;
}

#pragma mark - Data

- (void)reloadData {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray<NSDictionary *> *records = [[UCAppLogManager sharedManager] allLogs];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.logs removeAllObjects];
            [self.logs addObjectsFromArray:records];
            [self updateSearchResultsForSearchController:self.searchController];
        });
    });
}

- (void)startRefreshTimer {
    [self.refreshTimer invalidate];
    self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:2.0
                                                           target:self
                                                         selector:@selector(reloadData)
                                                         userInfo:nil
                                                          repeats:YES];
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.filteredLogs.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kCellIdentifier forIndexPath:indexPath];
    NSDictionary *record = self.filteredLogs[indexPath.row];
    NSString *text = record[@"logText"] ?: @"";
    NSString *timestamp = record[@"timestamp"] ?: @"";

    cell.backgroundColor = [UIColor blackColor];
    cell.textLabel.textColor = [UIColor whiteColor];
    cell.textLabel.font = [UIFont fontWithName:@"Menlo" size:11];
    cell.textLabel.numberOfLines = 3;
    cell.textLabel.text = [NSString stringWithFormat:@"[%@] %@", timestamp, text];
    cell.detailTextLabel.text = nil;
    return cell;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 64.0;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary *record = self.filteredLogs[indexPath.row];
    [self showDetailForRecord:record];
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        NSDictionary *record = self.filteredLogs[indexPath.row];
        NSInteger logId = [record[@"id"] integerValue];
        [[UCAppLogManager sharedManager] deleteLogById:logId];
        [self reloadData];
    }
}

#pragma mark - UISearchResultsUpdating

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    NSString *text = searchController.searchBar.text ?: @"";
    if (text.length == 0) {
        [self.filteredLogs removeAllObjects];
        [self.filteredLogs addObjectsFromArray:self.logs];
    } else {
        NSPredicate *predicate = [NSPredicate predicateWithBlock:^BOOL(NSDictionary *record, NSDictionary *bindings) {
            NSString *logText = record[@"logText"] ?: @"";
            return [logText localizedCaseInsensitiveContainsString:text];
        }];
        [self.filteredLogs removeAllObjects];
        [self.filteredLogs addObjectsFromArray:[self.logs filteredArrayUsingPredicate:predicate]];
    }
    [self.tableView reloadData];
}

#pragma mark - Actions

- (void)showDetailForRecord:(NSDictionary *)record {
    NSString *text = record[@"logText"] ?: @"";
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"日志详情"
                                                                   message:text
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [[UIPasteboard generalPasteboard] setString:text];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"导出本条" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self exportSingleRecord:record];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)exportAllTapped:(id)sender {
    if (self.isExporting) return;
    self.isExporting = YES;
    [[UCAppLogManager sharedManager] exportAllLogsFromViewController:self completion:^(BOOL success) {
        self.isExporting = NO;
        [self showToast:success ? @"导出成功" : @"导出失败或没有日志"];
    }];
}

- (void)exportSingleRecord:(NSDictionary *)record {
    if (self.isExporting) return;
    self.isExporting = YES;
    [[UCAppLogManager sharedManager] exportLogRecord:record fromViewController:self completion:^(BOOL success) {
        self.isExporting = NO;
        [self showToast:success ? @"导出成功" : @"导出失败"];
    }];
}

- (void)clearAllTapped:(id)sender {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"清除全部日志"
                                                                   message:@"确定删除所有运行日志？"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [[UCAppLogManager sharedManager] clearAllLogs];
        [self reloadData];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)settingsTapped:(id)sender {
    UCAppLogManager *manager = [UCAppLogManager sharedManager];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"日志设置"
                                                                   message:@"设置保留策略"
                                                            preferredStyle:UIAlertControllerStyleAlert];

    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"最大条数（默认5000）";
        textField.text = [NSString stringWithFormat:@"%ld", (long)manager.maxLogCount];
        textField.keyboardType = UIKeyboardTypeNumberPad;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"保留天数（默认7，0表示不限制）";
        textField.text = [NSString stringWithFormat:@"%ld", (long)manager.maxLogDays];
        textField.keyboardType = UIKeyboardTypeNumberPad;
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *countText = alert.textFields[0].text;
        NSString *daysText = alert.textFields[1].text;
        manager.maxLogCount = [countText integerValue] > 0 ? [countText integerValue] : 5000;
        manager.maxLogDays = [daysText integerValue] >= 0 ? [daysText integerValue] : 7;
        [manager cleanupIfNeeded];
        [self showToast:@"设置已保存"];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showToast:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:alert animated:YES completion:nil];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [alert dismissViewControllerAnimated:YES completion:nil];
        });
    });
}

@end
