TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = wallet

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = YSFDeviceReset

YSFDeviceReset_FILES = Tweak.xm
YSFDeviceReset_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
YSFDeviceReset_FRAMEWORKS = UIKit Foundation Security CoreFoundation
YSFDeviceReset_PRIVATE_FRAMEWORKS =

include $(THEOS_MAKE_PATH)/tweak.mk

# TrollFools 需要的是一个独立的 .dylib, 下面这个 target 帮你放到产物目录
after-install::
	@true

package-clean::
	@true
