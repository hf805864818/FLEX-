# FLEX++ - 独立注入版 Makefile
# 自动版本递增由 GitHub Actions CI 负责

# 版本号来自外部文件
include FLEXXXVersion

PACKAGE_IDENTIFIER = com.huami.flexxx
PACKAGE_NAME = FLEX++
PACKAGE_VERSION = $(FLEXXX_VERSION)
PACKAGE_ARCHITECTURE = iphoneos-arm64
PACKAGE_REVISION = 1
PACKAGE_SECTION = Tweaks
PACKAGE_DEPENDS = firmware (>= 14.0), mobilesubstrate
PACKAGE_DESCRIPTION = FLEX++ - 增强版iOS调试工具\n集性能监控/网络抓包/UI调试/逆向分析于一体

define Package/$(PACKAGE_IDENTIFIER)
  Package: com.huami.flexxx
  Name: FLEX++
  Version: $(FLEXXX_VERSION)
  Architecture: iphoneos-arm64
  Author: pxx917144686
  Section: Tweaks
  Depends: firmware (>= 14.0), mobilesubstrate
endef

export THEOS_PACKAGE_DIR = $(CURDIR)

# TARGET
ARCHS = arm64
TARGET = iphone:clang:latest:15.0

# 关闭严格错误
export DEBUG = 0
export ERROR_ON_WARNINGS = 0
export LOGOS_DEFAULT_GENERATOR = internal

# Rootless 配置
export THEOS_PACKAGE_SCHEME = rootless
THEOS_PACKAGE_INSTALL_PREFIX = /var/jb

# 目标进程（注入所有App）
INSTALL_TARGET_PROCESSES = SpringBoard

# 引入Theos
include $(THEOS)/makefiles/common.mk

# Tweak名称
TWEAK_NAME = FLEX++

# 主入口
$(TWEAK_NAME)_FILES = Tweak.xm

# FLEX源文件
FLEX_FILES := $(shell find FLEX -name '*.m' -o -name '*.mm' | grep -v 'FLEX/x/retdec' | grep -v 'FLEX/x/capstone')
$(TWEAK_NAME)_FILES += $(FLEX_FILES) FLEX/flex_fishhook.c

# Capstone引擎（反汇编）
CAPSTONE_CORE := $(shell find FLEX/x/capstone -maxdepth 1 -name "*.c")
CAPSTONE_ARM := $(shell find FLEX/x/capstone/arch/ARM -name "*.c")
CAPSTONE_ARM64 := $(shell find FLEX/x/capstone/arch/AArch64 -name "*.c")
$(TWEAK_NAME)_FILES += $(CAPSTONE_CORE) $(CAPSTONE_ARM) $(CAPSTONE_ARM64)

# 编译标志
$(TWEAK_NAME)_CFLAGS = -fobjc-arc -w
$(TWEAK_NAME)_CFLAGS += -Wno-deprecated-declarations -Wno-sign-compare -Wno-pointer-sign
$(TWEAK_NAME)_CFLAGS += -fobjc-runtime=ios-15.0
$(TWEAK_NAME)_CFLAGS += -DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_AARCH64 -DCAPSTONE_USE_SYS_DYN_MEM

# 框架
$(TWEAK_NAME)_FRAMEWORKS = UIKit Foundation Security Metal MetalKit CoreImage SwiftUI Combine
$(TWEAK_NAME)_FRAMEWORKS += AVFoundation WebKit QuartzCore CFNetwork Photos QuickLook LocalAuthentication UserNotifications

# 系统库
$(TWEAK_NAME)_LIBRARIES = sqlite3 z

# 链接器
$(TWEAK_NAME)_LDFLAGS += -Xlinker -no_adhoc_codesign -Xlinker -objc_abi_version -Xlinker 2
$(TWEAK_NAME)_LDFLAGS += -Wl,-w

# 头文件路径
$(TWEAK_NAME)_CFLAGS += -I$(THEOS_PROJECT_DIR)
$(TWEAK_NAME)_CFLAGS += -I$(THEOS_PROJECT_DIR)/FLEX
$(TWEAK_NAME)_CFLAGS += -I$(THEOS_PROJECT_DIR)/FLEX/x/capstone/include
$(TWEAK_NAME)_CCFLAGS = -std=c++17 -fno-rtti -fno-modules
$(TWEAK_NAME)_CCFLAGS += -I$(THEOS_PROJECT_DIR)/FLEX/x/capstone/include

# 预处理
$(TWEAK_NAME)_CFLAGS += -DDOKIT_FULL_BUILD=1

include $(THEOS_MAKE_PATH)/tweak.mk
