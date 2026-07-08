# FLEX++

增强版iOS App内调试工具，集性能监控、网络抓包、UI调试、逆向分析于一体。

## 功能

| 模块 | 功能 |
|------|------|
| 📊 性能监控 | CPU/内存/FPS/卡顿检测 |
| 🌐 网络调试 | 请求抓包 + Mock数据 + 弱网模拟(2G~断网) |
| 🎨 UI调试 | 3D视图层次(Lookin+Reveal) + 颜色吸管 + 对齐标尺 + 视图边框 |
| 🔍 逆向分析 | ARM64反汇编(CFG) + ClassDump + SSL抓包 + Hook检测 |
| 💥 崩溃监控 | Signal/Exception/KVO/UnrecognizedSelector 四种捕获 |
| 📋 日志系统 | 实时日志 + 过滤 + ASL/OSLog |
| 🗄️ 数据管理 | SQLite/Realm/Firebase/UserDefaults 浏览器 |
| 🛠️ 常用工具 | 沙盒浏览、API测试、推送测试、Cookie管理、缓存清理 |

## 安装

### 越狱设备
下载 [Release](https://github.com/hf805864818/FLEX-/releases) 中的 `.deb` 包安装。

### 未越狱
使用 TrollFools / Dopamine 等工具注入 `FLEX++.dylib`。

## 使用

- **双击状态栏** 呼出/隐藏调试面板
- 面板上 **长按拖拽手柄** 可移动面板位置
- 面板提供两行工具按钮：第一行是核心功能，第二行是逆向分析工具

## 自动构建

每次 push 到 main/master 分支会自动：
- 递增 patch 版本号
- 更新源码中的版本宏
- 编译生成 .deb 和 .dylib
- 创建 GitHub Release 并上传产物

手动触发构建时可选择 `major`/`minor`/`patch` 递增方式。

## 版本

当前版本见 [FLEXXXVersion](FLEXXXVersion)，源码版本号显示在工具栏右上角。

## 许可

基于原 FLEX 项目扩展，遵循项目原有许可。
