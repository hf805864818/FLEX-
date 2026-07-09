# FLEX++ 增强版 - 动态Hook / 内存扫描 / 函数拦截 开发文档

## 1. 现有架构分析

### 1.1 整体架构

```
Tweak.xm (入口: 双击状态栏)
  └── FLEXManager.showExplorer
        └── FLEXTabsViewController (第二行工具栏)
              └── "抓取" 按钮 → IZXShowDecryptPanelNow()
                    └── CapturePanelViewController ("逆向助手")
                          ├── UIPageViewController (横向滑动)
                          ├── 可滑动标签栏 (网络/解密/密钥/算法)
                          └── 4 个子 ViewController
```

### 1.2 现有标签页架构模板

每个标签页的创建遵循统一模式，以 "解密" 标签为例：

```objc
// 1. 定义列表 VC 子类
@interface CaptureDecryptListVC : CaptureListViewController
@end

@implementation CaptureDecryptListVC

- (instancetype)init {
    return [self initWithTableName:@"decrypt_data"           // DB 表名
                       scopeTitles:@[@"全部", @"自动解密", @"JS解码", @"HTTPS", @"RSA"]
                         tintColor:[UIColor colorWithRed:0.2 green:0.78 blue:0.4 alpha:1.0]];
}

- (BOOL)matchesScope:(NSInteger)scope text:(NSString *)text {
    // 按 scope 过滤数据项
}

- (UIViewController *)detailViewControllerForItem:(NSDictionary *)item {
    // 创建详情页
    return [[CaptureDetailViewController alloc] initWithText:text title:@"解密详情"];
}

@end
```

**基类 `CaptureListViewController` 提供的通用能力**：
- 数据加载：`[DatabaseManager queryAllRecordsFromTable:limit:]`
- 搜索过滤：内置 `UISearchController`
- Scope 切换：`scopeButtonTitles` 分段过滤
- 导出模式：`enterExportMode` / `cancelExportMode` / `performExport`
- 导航栏按钮：`updateExportTitle` 显示 "导出(N)"

### 1.3 数据流

```
Hook 层 (fishhook / ObjC Swizzle)
  → 构造日志文本 (含时间戳、参数、返回值等)
  → [DatabaseManager insertDataIntoTable:bundleID:text:]
    → SQLite 存储 (bundleID, longText, timestamp)
      → [DatabaseManager queryAllRecordsFromTable:limit:]
        → CaptureListViewController 展示
          → UCExportManager.exportItems: 导出 ZIP
```

### 1.4 现有 Hook 注册机制

```objc
// UCDecryptTool.m
+ (void)installDecryptHooksIfNeeded {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [[DatabaseManager sharedManager] createTables];  // 创建所有表
        RegisterCryptoHooks();        // C 函数 (fishhook)
        RegisterStreamingHashHooks(); // C 函数 (fishhook)
        RegisterOpenSSLHooks();       // C 函数 (fishhook)
        RegisterSSLHooks();           // C 函数 (fishhook)
        RegisterURLResponseHooks();   // ObjC Swizzle
        RegisterURLInterceptHooks();  // ObjC Swizzle + fishhook
    });
}
```

### 1.5 数据库表结构

所有数据表采用统一 schema：

```sql
CREATE TABLE IF NOT EXISTS <table_name> (
    bundleID TEXT,
    longText TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

现有表：`decrypt_data`, `crypto_keys`, `jiamisuanfa`, `url_responses`,
`ssl_certificates`, `ssl_challenges`, `ssl_psk`, `rsa_data`, `zhaiyao`, `hanmiyao`

### 1.6 导出机制

```objc
// UCExportManager.m
+ (void)exportItems:(NSArray<NSDictionary *> *)items
           tableName:(NSString *)tableName
  fromViewController:(UIViewController *)vc
          completion:(void (^)(BOOL))completion {
    // 1. 创建临时目录 /tmp/FLEXExport/<tableName>/
    // 2. 每条数据写入单独的 .txt 文件 (文件名 = 序号 + 时间戳)
    // 3. [CDZipWriter createZipAtPath:rootDir:files:] 打包为 ZIP
    // 4. UIActivityViewController 系统分享
}
```

### 1.7 现有功能开关机制

```sql
CREATE TABLE IF NOT EXISTS kaiguan (
    bundleID TEXT PRIMARY KEY,
    zongkaiguan INTEGER DEFAULT 0,           -- 总开关
    zhaiyaokaiguan INTEGER DEFAULT 0,        -- 网络抓包
    hanmiyaokaiguan INTEGER DEFAULT 0,       -- HMAC密钥
    jiamisuanfakaiguan INTEGER DEFAULT 0,    -- 加密算法
    ssl3kaiguan INTEGER DEFAULT 0,           -- SSL证书
    proxy_bypass INTEGER DEFAULT 0,          -- 代理绕过
    rsa_encrypt INTEGER DEFAULT 0,           -- RSA加密
    rsa_decrypt INTEGER DEFAULT 0,           -- RSA解密
    rsa_sign INTEGER DEFAULT 0               -- RSA签名
);
```

---

## 2. 新增功能开发计划

### 2.1 总览

| 功能 | 标签名 | DB 表名 | Hook 方式 | Scope 分类 |
|------|--------|---------|-----------|-----------|
| 动态Hook | 动态Hook | `dynamic_hook` | fishhook + ObjC Swizzle (通用框架) | 全部/C函数/OC方法/Swift方法/系统API |
| 内存扫描 | 内存扫描 | `memory_scan` | `vm_region_recurse` + `mach_vm_read` | 全部/字符串/密钥格式/加密常量/证书 |
| 函数拦截 | 函数拦截 | `func_intercept` | fishhook + inline hook | 全部/加密/签名/网络/文件/数据库 |

### 2.2 标签栏扩展

在 `setupScrollableTabBar` 的 `titles` 数组中追加三个标签：

```objc
NSArray *titles = @[@"网络", @"解密", @"密钥", @"算法",
                    @"动态Hook", @"内存扫描", @"函数拦截"];
```

对应的 `_viewControllers` 追加：

```objc
DynamicHookListVC *hookVC = [[DynamicHookListVC alloc] init];
MemoryScanListVC *memVC = [[MemoryScanListVC alloc] init];
FuncInterceptListVC *interceptVC = [[FuncInterceptListVC alloc] init];
_viewControllers = @[networkVC, decryptVC, keyVC, cryptoVC,
                     hookVC, memVC, interceptVC];
```

---

## 3. 模块一：动态Hook 引擎

### 3.1 功能描述

提供运行时交互式 Hook 能力，让用户可以在 UI 上：
- 搜索并选择目标类/方法
- 一键 Hook 指定方法
- 实时查看 Hook 拦截到的参数和返回值
- 支持导出捕获数据

### 3.2 新增文件

```
FLEX/x/DynamicHook/
├── UCDynamicHookEngine.h     # Hook 引擎核心 (安装/卸载/查询)
├── UCDynamicHookEngine.m
├── UCDynamicHookListVC.h     # 列表展示 VC (按 CaptureListViewController 模式)
├── UCDynamicHookListVC.m
├── UCHookConfigVC.h          # Hook 配置界面 (选择类/方法)
└── UCHookConfigVC.m
```

### 3.3 数据库

```sql
-- DatabaseManager.m 的 createTables 中追加
@"CREATE TABLE IF NOT EXISTS dynamic_hook (bundleID TEXT, longText TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)",

-- 功能开关表 kaiguan 追加字段
-- dynamic_hook_enabled INTEGER DEFAULT 0
```

### 3.4 UCDynamicHookEngine 设计

```objc
@interface UCDynamicHookEngine : NSObject

+ (instancetype)sharedEngine;

// Hook 管理
- (NSArray<NSString *> *)hookableClasses;           // 可 Hook 的类列表
- (NSArray<NSString *> *)methodsForClass:(NSString *)className;  // 类的方法列表
- (BOOL)installHookOnClass:(NSString *)className
                    method:(NSString *)methodName
                     isClassMethod:(BOOL)isClassMethod;  // 安装 Hook
- (BOOL)removeHookOnClass:(NSString *)className
                   method:(NSString *)methodName;         // 卸载 Hook
- (NSArray<NSDictionary *> *)activeHooks;                 // 当前活跃 Hook 列表

// 数据记录 (Hook 被触发时调用)
- (void)recordHookTrigger:(NSString *)className
                   method:(NSString *)methodName
                     args:(NSArray *)args
                 returnValue:(id)retVal;

@end
```

**Hook 实现策略**：

| 目标类型 | 技术方案 | 说明 |
|---------|---------|------|
| OC 实例方法 | `method_setImplementation` + 保存原 IMP | 替换方法实现，在原方法前后插入记录代码 |
| OC 类方法 | 同上，操作 metaclass | `object_getClass([cls class])` |
| C 函数 | fishhook `rebind_symbols` | 替换 `__DATA,__la_symbol_ptr` 中的指针 |
| 批量系统 API | 预置 Hook 配置 (加密/网络等) | 一键 Hook 常用 API 组合 |

**Hook 记录格式**：

```
[Hook] 2026-07-09 14:30:00
类名: NSData (实例方法)
方法: -AES128EncryptWithKey:
参数[0] key: "mysecretkey123456"
返回值: <a1b2c3d4...> (32 bytes)
耗时: 0.023ms
```

### 3.5 UCDynamicHookListVC

继承 `CaptureListViewController`，模式与现有标签一致：

```objc
@interface UCDynamicHookListVC : CaptureListViewController
@end

@implementation UCDynamicHookListVC

- (instancetype)init {
    return [self initWithTableName:@"dynamic_hook"
                       scopeTitles:@[@"全部", @"C函数", @"OC方法", @"Swift方法", @"系统API"]
                         tintColor:[UIColor colorWithRed:0.3 green:0.5 blue:1.0 alpha:1.0]];
}

- (BOOL)matchesScope:(NSInteger)scope text:(NSString *)text {
    NSString *low = text.lowercaseString;
    switch (scope) {
        case 1: return [low containsString:@"[c函数]"];
        case 2: return [low containsString:@"[oc方法]"] || [low containsString:@"实例方法"] || [low containsString:@"类方法"];
        case 3: return [low containsString:@"[swift]"];
        case 4: return [low containsString:@"[系统api]"] || [low containsString:@"system"];
        default: return YES;
    }
}

- (UIViewController *)detailViewControllerForItem:(NSDictionary *)item {
    NSString *text = item[@"longText"] ?: @"";
    return [[CaptureDetailViewController alloc] initWithText:text title:@"Hook详情"];
}

@end
```

### 3.6 注册到入口

```objc
// UCDecryptTool.h 新增声明
extern void RegisterDynamicHookEngine(void);

// UCDecryptTool.m installDecryptHooksIfNeeded 中追加
RegisterDynamicHookEngine();
```

### 3.7 导航栏按钮

在 `CapturePanelViewController` 中新增一个右侧按钮，用于打开 Hook 配置界面：

```objc
// updateRightBarButtonItems 中追加
UIBarButtonItem *hookConfig = [[UIBarButtonItem alloc]
    initWithImage:[UIImage systemImageNamed:@"link"]
    style:UIBarButtonItemStylePlain
    target:self
    action:@selector(hookConfigTapped)];

// 调整 rightBarButtonItems 数组
self.navigationItem.rightBarButtonItems = @[trash, space, hookConfig, space, settings, space, self.exportButton];
```

---

## 4. 模块二：内存扫描 引擎

### 4.1 功能描述

遍历进程虚拟内存空间，搜索特定模式：
- 硬编码字符串 (域名、密钥)
- 十六进制模式 (AES Key: 16/24/32 字节 hex)
- 正则匹配 (Base64 密钥、JWT Token)
- 证书数据 (PEM/DER 格式)
- 加密常量 (S-Box、IV)

### 4.2 新增文件

```
FLEX/x/MemoryScan/
├── UCMemoryScanner.h         # 扫描引擎核心
├── UCMemoryScanner.m
├── UCMemoryScanListVC.h      # 扫描结果列表 VC
├── UCMemoryScanListVC.m
├── UCMemoryScanConfigVC.h    # 扫描参数配置
└── UCMemoryScanConfigVC.m
```

### 4.3 数据库

```sql
@"CREATE TABLE IF NOT EXISTS memory_scan (bundleID TEXT, longText TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)",
```

### 4.4 UCMemoryScanner 设计

```objc
@interface UCMemoryScanner : NSObject

+ (instancetype)sharedScanner;

// 扫描控制
- (void)startScanWithConfig:(NSDictionary *)config
                   progress:(void (^)(float progress, NSString *current))progressBlock
                 completion:(void (^)(NSUInteger resultCount))completionBlock;
- (void)stopScan;

// 扫描模式
typedef NS_ENUM(NSInteger, UCMemoryScanMode) {
    UCMemoryScanModeString,      // ASCII/UTF8 字符串搜索
    UCMemoryScanModeHexPattern,  // 十六进制模式匹配
    UCMemoryScanModeRegex,       // 正则表达式匹配
    UCMemoryScanModeCertificate, // PEM/DER 证书数据
    UCMemoryScanModeCryptoConst, // 加密常量 (S-Box/IV)
};

// 预置扫描规则
@property (nonatomic, readonly) NSArray<NSDictionary *> *presetRules;
// 预设规则包括:
//  - 16/24/32 字节 hex 序列 (可能为 AES Key)
//  - 64 字节 hex (可能为 SHA256)
//  - Base64 长度 > 40 的字符串 (可能为编码密钥)
//  - -----BEGIN (证书 PEM 头)
//  - RSA/DSA/EC PRIVATE KEY (密钥文件头)
//  - JWT eyJ 开头 Token

@end
```

**扫描实现核心逻辑**：

```
1. 获取所有已加载 Mach-O 映像 (dyld)
2. 遍历每个映像的内存区域 (vm_region_recurse_64)
3. 只扫描可读区域 (VM_PROT_READ)
4. 跳过系统库 (可选配置)
5. 对每个区域执行模式匹配
6. 匹配命中时记录: 地址、映像名、附近数据 (前后 128 字节)、匹配类型
```

**扫描结果记录格式**：

```
[MemScan] 2026-07-09 14:30:00
映像: libapp.so
地址: 0x104a3c000 + 0x2f40
类型: 十六进制模式 (32字节)
匹配: a1b2c3d4e5f6... (32 hex)
附近数据 (前64字节):
0000: 48656c6c 6f576f72 6c640000 ...
附近数据 (后64字节):
0020: 00010203 04050607 08090a0b ...
```

### 4.5 UCMemoryScanListVC

```objc
@interface UCMemoryScanListVC : CaptureListViewController
@end

@implementation UCMemoryScanListVC

- (instancetype)init {
    return [self initWithTableName:@"memory_scan"
                       scopeTitles:@[@"全部", @"字符串", @"密钥格式", @"加密常量", @"证书"]
                         tintColor:[UIColor colorWithRed:1.0 green:0.4 blue:0.6 alpha:1.0]];
}

- (BOOL)matchesScope:(NSInteger)scope text:(NSString *)text {
    NSString *low = text.lowercaseString;
    switch (scope) {
        case 1: return [low containsString:@"字符串"];
        case 2: return [low containsString:@"密钥"] || [low containsString:@"aes"] || [low containsString:@"hex"];
        case 3: return [low containsString:@"加密常量"] || [low containsString:@"s-box"];
        case 4: return [low containsString:@"证书"] || [low containsString:@"pem"] || [low containsString:@"begin"];
        default: return YES;
    }
}

- (UIViewController *)detailViewControllerForItem:(NSDictionary *)item {
    NSString *text = item[@"longText"] ?: @"";
    return [[CaptureDetailViewController alloc] initWithText:text title:@"扫描详情"];
}

@end
```

### 4.6 注册

```objc
// 内存扫描不需要 register 到 UCDecryptTool
// 它是用户手动触发的，不是自动 Hook
// 通过 CapturePanelViewController 中新增按钮触发
```

---

## 5. 模块三：函数拦截 引擎

### 5.1 功能描述

拦截常见系统 API 的函数调用，追踪数据流：
- 加密 API (CCCrypt/SecEncryptTransform/EVP_Encrypt)
- 网络 API (NSURLSession/CFNetwork)
- 文件 I/O (NSData writeToFile/NSFileHandle)
- 数据库操作 (sqlite3_exec/sqlite3_prepare)
- 进程间通信 (XPC/NSConnection)

**与现有 "解密/密钥/算法" 标签的区别**：
- 现有标签捕获的是**加密操作的密钥和算法细节**
- "函数拦截" 做的是**更广泛的系统调用追踪**，不仅限于加解密，还包括网络、文件、数据库等

### 5.2 新增文件

```
FLEX/x/FuncIntercept/
├── UCFuncInterceptEngine.h   # 函数拦截引擎
├── UCFuncInterceptEngine.m
├── UCFuncInterceptListVC.h   # 拦截记录列表 VC
├── UCFuncInterceptListVC.m
├── UCCallTracer.h            # 调用链追踪器 (记录调用栈)
└── UCCallTracer.m
```

### 5.3 数据库

```sql
@"CREATE TABLE IF NOT EXISTS func_intercept (bundleID TEXT, longText TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)",

-- 功能开关表 kaiguan 追加
-- func_intercept_enabled INTEGER DEFAULT 0
```

### 5.4 UCFuncInterceptEngine 设计

```objc
@interface UCFuncInterceptEngine : NSObject

+ (instancetype)sharedEngine;

// 拦截类别
typedef NS_ENUM(NSInteger, UCInterceptCategory) {
    UCInterceptCategoryCrypto,    // 加密相关
    UCInterceptCategoryNetwork,   // 网络相关
    UCInterceptCategoryFileIO,    // 文件 I/O
    UCInterceptCategoryDatabase,  // 数据库操作
    UCInterceptCategoryIPC,       // 进程间通信
};

// 拦截控制
- (void)installCategory:(UCInterceptCategory)category;  // 安装拦截
- (void)removeCategory:(UCInterceptCategory)category;    // 卸载拦截
- (BOOL)isCategoryActive:(UCInterceptCategory)category;

// 预置拦截目标
// 加密: CCCrypt, SecEncryptTransform, SecDecryptTransform, EVP_EncryptInit_ex
// 网络: connect, getaddrinfo, CFReadStreamOpen, NSURLSession dataTask
// 文件: open, write, NSData writeToFile, NSFileManager createFile
// 数据库: sqlite3_exec, sqlite3_prepare_v2, sqlite3_step
// IPC: xpc_connection_send_message, CFMessagePortCreateRemote

@end
```

**拦截记录格式**：

```
[Intercept] 2026-07-09 14:30:00
类别: 加密
函数: CCCrypt (C 函数, CommonCrypto)
操作: 加密
算法: AES-128-CBC
参数[0] op: kCCEncrypt (0)
参数[1] alg: kCCAlgorithmAES128 (0)
参数[2] options: kCCOptionPKCS7Padding (1)
参数[3] key: "mykey1234567890" (16 bytes)
参数[4] keyLength: 16
参数[5] iv: "0123456789abcdef" (16 bytes)
返回值: kCCSuccess (0)

调用栈:
  #0 CCCrypt (CommonCrypto)
  #1 -[DataEncryptor encrypt:] (libapp.so + 0x4a2c)
  #2 -[HttpClient sendRequest:] (libapp.so + 0x8f10)
```

### 5.5 UCFuncInterceptListVC

```objc
@interface UCFuncInterceptListVC : CaptureListViewController
@end

@implementation UCFuncInterceptListVC

- (instancetype)init {
    return [self initWithTableName:@"func_intercept"
                       scopeTitles:@[@"全部", @"加密", @"签名", @"网络", @"文件", @"数据库"]
                         tintColor:[UIColor colorWithRed:0.1 green:0.7 blue:0.9 alpha:1.0]];
}

- (BOOL)matchesScope:(NSInteger)scope text:(NSString *)text {
    NSString *low = text.lowercaseString;
    switch (scope) {
        case 1: return [low containsString:@"加密"] || [low containsString:@"encrypt"] || [low containsString:@"decrypt"];
        case 2: return [low containsString:@"签名"] || [low containsString:@"sign"] || [low containsString:@"hmac"];
        case 3: return [low containsString:@"网络"] || [low containsString:@"http"] || [low containsString:@"connect"];
        case 4: return [low containsString:@"文件"] || [low containsString:@"write"] || [low containsString:@"file"];
        case 5: return [low containsString:@"数据库"] || [low containsString:@"sqlite"] || [low containsString:@"db"];
        default: return YES;
    }
}

- (UIViewController *)detailViewControllerForItem:(NSDictionary *)item {
    NSString *text = item[@"longText"] ?: @"";
    return [[CaptureDetailViewController alloc] initWithText:text title:@"拦截详情"];
}

@end
```

### 5.6 调用栈追踪 (UCCallTracer)

```objc
@interface UCCallTracer : NSObject

+ (instancetype)sharedTracer;

// 获取当前调用栈 (符号化)
// 返回最多 10 层调用帧，过滤掉 Hook 自身的方法
- (NSString *)captureCallStack:(NSUInteger)maxFrames;

// 符号化地址
- (NSString *)symbolicateAddress:(void *)address;

@end
```

使用 `backtrace_symbols()` 获取调用栈，配合 `dladdr()` 定位所属映像。

### 5.7 注册

```objc
// UCDecryptTool.h
extern void RegisterFuncInterceptEngine(void);

// UCDecryptTool.m installDecryptHooksIfNeeded 中追加
RegisterFuncInterceptEngine();
```

---

## 6. UI 集成方案

### 6.1 CapturePanelViewController 修改点

| 位置 | 修改内容 |
|------|---------|
| `setupScrollableTabBar` | `titles` 数组追加 3 个标签 |
| `viewDidLoad` | `_viewControllers` 数组追加 3 个新 VC |
| `trashTapped` | `switch(currentIndex)` 增加 3 个 case (case 4/5/6) |
| `exportTapped` | `CaptureTab` 枚举扩展 (已有 4 个值，新 tab 自动走 `CaptureListViewController` 分支) |
| `settingsTapped` → `CaptureSettingsVC` | 新增 3 个功能开关项 |

### 6.2 CaptureTab 枚举扩展

```objc
typedef NS_ENUM(NSInteger, CaptureTab) {
    CaptureTabNetwork = 0,
    CaptureTabDecrypt,
    CaptureTabKeys,
    CaptureTabCrypto,
    CaptureTabDynamicHook,   // 新增
    CaptureTabMemoryScan,    // 新增
    CaptureTabFuncIntercept, // 新增
};
```

### 6.3 垃圾箱操作扩展

```objc
- (void)trashTapped {
    // ...
    switch (self.currentIndex) {
        // ... existing cases ...
        case CaptureTabDynamicHook: {
            title = @"清除Hook记录";
            msg = @"确定清除所有动态Hook记录？";
            action = ^{
                [[DatabaseManager sharedManager] clearTable:@"dynamic_hook"];
                [(CaptureListViewController *)self.viewControllers[CaptureTabDynamicHook] reloadData];
                // 发送通知
            };
            break;
        }
        case CaptureTabMemoryScan: {
            title = @"清除扫描记录";
            msg = @"确定清除所有内存扫描记录？";
            action = ^{
                [[DatabaseManager sharedManager] clearTable:@"memory_scan"];
                [(CaptureListViewController *)self.viewControllers[CaptureTabMemoryScan] reloadData];
            };
            break;
        }
        case CaptureTabFuncIntercept: {
            title = @"清除拦截记录";
            msg = @"确定清除所有函数拦截记录？";
            action = ^{
                [[DatabaseManager sharedManager] clearTable:@"func_intercept"];
                [(CaptureListViewController *)self.viewControllers[CaptureTabFuncIntercept] reloadData];
            };
            break;
        }
    }
}
```

### 6.4 功能开关扩展

在 `CaptureSettingsVC` 的 `switchItems` 数组中追加：

```objc
[CaptureSwitchItem itemWithTitle:@"动态Hook" key:@"dynamic_hook_enabled"
                            desc:@"运行时Hook任意方法并捕获参数/返回值" default:NO],
[CaptureSwitchItem itemWithTitle:@"函数拦截" key:@"func_intercept_enabled"
                            desc:@"拦截系统API调用追踪数据流" default:NO],
```

内存扫描不需要开关（它是手动触发的，不是自动 Hook）。

---

## 7. 导出机制

三个新功能**无需修改** `UCExportManager`。现有的 `exportItems:tableName:` 方法已经支持任何表名：

| 功能 | 表名 | 导出文件名 |
|------|------|-----------|
| 动态Hook | `dynamic_hook` | `FLEX_dynamichook_N条.zip` |
| 内存扫描 | `memory_scan` | `FLEX_memoryscan_N条.zip` |
| 函数拦截 | `func_intercept` | `FLEX_funcintercept_N条.zip` |

`performExport` 中传入的 `tableName` 自动决定导出内容。

---

## 8. 编译配置

### 8.1 Makefile

现有 Makefile 使用 `find FLEX -name '*.m' -o -name '*.mm'` 自动包含所有源文件，新增的 `.m` 文件会自动被编译，**无需修改 Makefile**。

### 8.2 头文件路径

由于 Makefile 已有 `-I$(THEOS_PROJECT_DIR)/FLEX`，新增头文件可直接用 `#import "x/DynamicHook/UCDynamicHookEngine.h"` 引用。

---

## 9. 文件结构总览

```
FLEX/x/
├── Decrypt/                    # 现有 (不改)
├── DynamicHook/                # 新增
│   ├── UCDynamicHookEngine.h
│   ├── UCDynamicHookEngine.m
│   └── UCHookConfigVC.h
│   └── UCHookConfigVC.m
├── MemoryScan/                 # 新增
│   ├── UCMemoryScanner.h
│   ├── UCMemoryScanner.m
│   └── UCMemoryScanConfigVC.h
│   └── UCMemoryScanConfigVC.m
├── FuncIntercept/              # 新增
│   ├── UCFuncInterceptEngine.h
│   ├── UCFuncInterceptEngine.m
│   ├── UCCallTracer.h
│   └── UCCallTracer.m
├── ClassDump/                  # 现有 (不改)
├── Disassembler/               # 现有 (不改)
├── filza/                      # 现有 (不改)
├── Shared/                     # 现有 (不改)
└── capstone/                   # 现有 (不改)
```

### 需要修改的现有文件

| 文件 | 修改量 | 说明 |
|------|--------|------|
| `FLEX/x/Decrypt/CapturePanel.m` | ~50 行 | 追加 tab、垃圾箱 case、开关项 |
| `FLEX/x/Decrypt/UCDecryptTool.h` | ~5 行 | 声明新 Register 函数 |
| `FLEX/x/Decrypt/UCDecryptTool.m` | ~3 行 | 调用新 Register 函数 |
| `FLEX/x/Decrypt/DatabaseManager.m` | ~10 行 | 新增表和开关字段 |

---

## 10. 实施顺序建议

| 阶段 | 内容 | 预估工作量 |
|------|------|-----------|
| 1 | `DatabaseManager` 新增表 + 开关字段 | 小 |
| 2 | `CapturePanel.m` 追加 3 个标签 VC 子类声明 | 小 |
| 3 | `CapturePanel.m` 扩展 tab 枚举 + 标签栏 + 垃圾箱 + 开关 | 中 |
| 4 | 模块三：`FuncIntercept` (复用现有 fishhook 模式，风险最低) | 中 |
| 5 | 模块一：`DynamicHook` (需要 UI 配置界面) | 大 |
| 6 | 模块二：`MemoryScan` (独立模块，不影响现有 Hook) | 中 |
| 7 | 集成测试 + 导出验证 | 小 |

**推荐先做模块三（函数拦截）**，因为它与现有的 `CryptoCapture` / `URLIntercept` 模式最接近，是现有 fishhook 体系的自然扩展。

---

## 11. 关键设计决策

| 决策 | 理由 |
|------|------|
| 三个功能各自独立标签而非合并 | 功能领域不同，用户使用场景互斥，独立标签便于按需查看 |
| 复用 `CaptureListViewController` 基类 | 已有搜索/过滤/分 scope/导出/详情页/垃圾箱清除等完整能力 |
| 动态 Hook 用 `method_setImplementation` | 比 fishhook 更适合 OC 方法级的精确控制，且支持运行时动态安装/卸载 |
| 内存扫描手动触发 | 扫描开销大（遍历 GB 级内存），不适合自动执行 |
| 函数拦截复用 fishhook 模式 | 与现有 `CryptoCapture` 等代码风格一致，维护成本最低 |
