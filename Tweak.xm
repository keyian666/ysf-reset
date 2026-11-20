// YSFDeviceReset —— 云闪付 (com.unionpay.chsp) 设备身份重置
// 目标: iOS 15.x + TrollStore + TrollFools 注入
//
// 原理(全部来自 YSF 10.3.8 二进制符号验证):
//   1) 清 Keychain —— 数美 SMID / 极光 JCore deviceID / 云闪付 UUID 全落在这里,删 App 不删 Keychain
//   2) 换 IDFV / IDFA —— 数美设备指纹的主要输入
//   3) 清 NSUserDefaults / 缓存里的 deviceId-uuid-idfa-smid 类键
//   4) 压掉越狱检测: isJailBreak / hasJailbreakFile / authorityWithJailBreakFlag: 等
//
// 关键设计: 只在"首次运行"重滚一次, 之后保持稳定。
//   每次都换 ID = 典型作弊特征, 反而更容易被数美打分打死。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>

// Logos 展开 %hook 时会把类名直接当类型用:
//   static NSUUID * _logos_method$ASIdentifierManager$advertisingIdentifier(ASIdentifierManager * self, SEL _cmd)
// UIDevice 由 UIKit 提供声明, 但 ASIdentifierManager 在 AdSupport 里,
// 少了这一句就是 "unknown type name 'ASIdentifierManager'", make 直接以 2 退出。
@class ASIdentifierManager;

#pragma mark - ========== 锚点 ==========

// 锚点存放在 App 沙盒 Documents 里:
//   - 删 App 时一并消失, 语义上正好等于"这是一台新设备"
//   - 不在 Keychain, 所以不会被 purge 逻辑误删
static NSString *YSFAnchorPath(void) {
    static NSString *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *base = docs.count ? docs[0] : NSTemporaryDirectory();
        p = [base stringByAppendingPathComponent:@".ysf_anchor"];
    });
    return p;
}

// 读取或生成锚点。返回值长度恒为 36 的 UUID 字符串。
static NSString *YSFAnchor(void) {
    static NSString *anchor = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *path = YSFAnchorPath();
        NSString *s = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
        if (s.length == 36) {
            anchor = [s copy];
            return;
        }
        anchor = [[[NSUUID UUID] UUIDString] copy];
        [anchor writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    });
    return anchor;
}

// 把锚点 + salt 派生成一个稳定的 UUID。
// 同一个进程、不同运行之间都一致 —— 这是"新设备"该有的样子。
static NSUUID *YSFDeriveUUID(const char *salt) {
    NSString *seed = [NSString stringWithFormat:@"%@|%s", YSFAnchor(), salt];
    NSData *data = [seed dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char d[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, d);

    unsigned char u[16];
    memcpy(u, d, 16);
    u[6] = (unsigned char)((u[6] & 0x0F) | 0x40);  // version 4
    u[8] = (unsigned char)((u[8] & 0x3F) | 0x80);  // RFC4122 variant
    return [[NSUUID alloc] initWithUUIDBytes:u];
}

static inline NSString *YSFDeriveUUIDString(const char *salt) {
    return [YSFDeriveUUID(salt) UUIDString];
}

#pragma mark - ========== Keychain 清空 ==========

// 只清"本 App access group 内"的条目 —— 注入的 dylib 跑在云闪付进程里,
// access group 天然合法, 不需要伪造任何 entitlement。
static void YSFPurgeKeychain(void) {
    NSArray *classes = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity,
    ];

    for (id cls in classes) {
        CFTypeRef found = NULL;
        NSDictionary *query = @{
            (__bridge id)kSecClass:            cls,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
        };
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, &found);
        if (st != errSecSuccess || found == NULL) continue;

        NSArray *items = (__bridge_transfer NSArray *)found;
        for (NSDictionary *attr in items) {
            if (![attr isKindOfClass:[NSDictionary class]]) continue;

            NSMutableDictionary *del = [@{(__bridge id)kSecClass: cls} mutableCopy];
            NSArray *idKeys = @[
                (__bridge id)kSecAttrService,
                (__bridge id)kSecAttrAccount,
                (__bridge id)kSecAttrAccessGroup,
                (__bridge id)kSecAttrGeneric,
                (__bridge id)kSecAttrApplicationTag,
                (__bridge id)kSecAttrServer,
                (__bridge id)kSecAttrProtocol,
            ];
            for (NSString *k in idKeys) {
                if (attr[k]) del[k] = attr[k];
            }

            // 只给了 class 的 query 会拒绝删除, 跳过没有可用标识的条目
            if (del.count <= 1) continue;
            SecItemDelete((__bridge CFDictionaryRef)del);
        }
    }
}

#pragma mark - ========== NSUserDefaults / 缓存清理 ==========

// 二进制里出现过的持久化键名(节选): deviceId / device_id / _deviceIdHead /
// regRandomUUID / app_uuid / uuidStr / sm_device_id / smId / SimulateIDFA /
// BOOTUUID / dSYMUUID / JCoreKeychainDeviceIDKey ...
static BOOL YSFKeyLooksLikeIdentity(NSString *key) {
    static NSArray<NSString *> *needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[ @"device", @"uuid", @"idfa", @"idfv", @"smid", @"sm_id",
                     @"smdevice", @"jcore", @"jpush", @"regrandom", @"bootuuid",
                     @"udid", @"nas", @"imei", @"fingerprint", @"token" ];
    });

    NSString *lk = key.lowercaseString;
    for (NSString *n in needles) {
        if ([lk containsString:n]) return YES;
    }
    return NO;
}

static void YSFPurgeDefaults(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    for (NSString *k in all.allKeys) {
        if (YSFKeyLooksLikeIdentity(k)) {
            [ud removeObjectForKey:k];
        }
    }
    [ud synchronize];

    // 各业务域可能各自建了 suite
    NSArray *suites = @[ @"com.unionpay.chsp", @"com.ishumei.antifraud",
                         @"cn.jpush", @"com.unionpay" ];
    for (NSString *s in suites) {
        NSUserDefaults *sud = [[NSUserDefaults alloc] initWithSuiteName:s];
        if (!sud) continue;
        NSDictionary *d = [sud dictionaryRepresentation];
        for (NSString *k in d.allKeys) {
            if (YSFKeyLooksLikeIdentity(k)) [sud removeObjectForKey:k];
        }
        [sud synchronize];
    }
}

static void YSFPurgeCaches(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *libs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    if (!libs.count) return;

    NSString *lib = libs[0];
    // 这两个目录删掉等价于"干净重装", 且系统会在下次启动时重建
    for (NSString *sub in @[ @"Caches", @"Preferences", @"WebKit", @"HTTPStorages" ]) {
        NSString *p = [lib stringByAppendingPathComponent:sub];
        NSError *err = nil;
        if ([fm fileExistsAtPath:p]) {
            [fm removeItemAtPath:p error:&err];
        }
    }
}

#pragma mark - ========== 通用 swizzle 工具 ==========

// 把指定 selector (不论它定义在哪个类上) 改成返回固定对象。
// 用于 GetHkeDeviceIdentifierV7/V8/V8Strong/V8WeakWithArg: 这类银联 ISOpenSDK 方法。
static void YSFSwizzleSelectorReturningObject(const char *selCStr, id (^value)(void)) {
    SEL sel = sel_registerName(selCStr);
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return;

    for (unsigned int i = 0; i < count; i++) {
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(classes[i], &mcount);
        if (!methods) continue;

        for (unsigned int j = 0; j < mcount; j++) {
            if (method_getName(methods[j]) != sel) continue;

            NSUInteger nargs = method_getNumberOfArguments(methods[j]) - 2;
            IMP imp = NULL;
            switch (nargs) {
                case 0: imp = imp_implementationWithBlock(^id(id self){ return value(); }); break;
                case 1: imp = imp_implementationWithBlock(^id(id self, id a){ return value(); }); break;
                case 2: imp = imp_implementationWithBlock(^id(id self, id a, id b){ return value(); }); break;
                case 3: imp = imp_implementationWithBlock(^id(id self, id a, id b, id c){ return value(); }); break;
                default: break;
            }
            if (imp) method_setImplementation(methods[j], imp);
        }
        free(methods);
    }
    free(classes);
}

// 把指定 selector 改成返回 NO。
// 用于 isJailBreak / hasJailbreakFile / hasMobileSubstrate / isRooted /
// p_isJailBreak1 / p_isJailBreak2 / isJailBreakWithPtrace:
static void YSFSwizzleSelectorReturningNO(const char *selCStr) {
    SEL sel = sel_registerName(selCStr);
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return;

    for (unsigned int i = 0; i < count; i++) {
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(classes[i], &mcount);
        if (!methods) continue;

        for (unsigned int j = 0; j < mcount; j++) {
            if (method_getName(methods[j]) != sel) continue;

            NSUInteger nargs = method_getNumberOfArguments(methods[j]) - 2;
            IMP imp = NULL;
            switch (nargs) {
                case 0: imp = imp_implementationWithBlock(^BOOL(id self){ return NO; }); break;
                case 1: imp = imp_implementationWithBlock(^BOOL(id self, id a){ return NO; }); break;
                case 2: imp = imp_implementationWithBlock(^BOOL(id self, id a, id b){ return NO; }); break;
                default: break;
            }
            if (imp) method_setImplementation(methods[j], imp);
        }
        free(methods);
    }
    free(classes);
}

static BOOL YSFAnyClassImplementsSelector(NSString *selName) {
    SEL sel = NSSelectorFromString(selName);
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return NO;
    BOOL found = NO;
    for (unsigned int i = 0; i < count && !found; i++) {
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(classes[i], &mcount);
        for (unsigned int j = 0; j < mcount; j++) {
            if (method_getName(methods[j]) == sel) { found = YES; break; }
        }
        if (methods) free(methods);
    }
    free(classes);
    return found;
}

#pragma mark - ========== 钩子: 原生标识 ==========

%hook UIDevice
- (NSUUID *)identifierForVendor {
    return YSFDeriveUUID("idfv");
}
%end

%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    return YSFDeriveUUID("idfa");
}
- (BOOL)isAdvertisingTrackingEnabled {
    return YES;
}
%end

// 极光 SimulateIDFA 走的是自己的 keychain 键, 键已被清空,
// 首次调用会重新生成 —— 不需要额外 hook。

#pragma mark - ========== 启动逻辑 ==========

%ctor {
    @autoreleasepool {
        NSString *anchorPath = YSFAnchorPath();
        NSString *rerollPath = [[anchorPath stringByDeletingLastPathComponent]
                                stringByAppendingPathComponent:@".ysf_reroll"];
        NSFileManager *fm = [NSFileManager defaultManager];

        BOOL fresh = ![fm fileExistsAtPath:anchorPath];
        BOOL reroll = [fm fileExistsAtPath:rerollPath];

        if (fresh || reroll) {
            // 顺序很重要: 先清 keychain, 再清 defaults, 最后落锚点。
            // 任何一个业务 SDK 在 didFinishLaunching 里读 keychain 时,
            // 看到的都已经是空的了。
            YSFPurgeKeychain();
            YSFPurgeDefaults();
            YSFPurgeCaches();
            (void)YSFAnchor();               // 写入新锚点
            if (reroll) [fm removeItemAtPath:rerollPath error:NULL];
        }

        // ---- 银联 ISOpenSDK 设备标识 (selector 名带冒号, 是 ObjC 方法) ----
        YSFSwizzleSelectorReturningObject("GetHkeDeviceIdentifierV8StrongWithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8-strong");
        });
        YSFSwizzleSelectorReturningObject("GetHkeDeviceIdentifierV8WeakWithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8-weak");
        });
        YSFSwizzleSelectorReturningObject("GetHkeDeviceIdentifierV8WithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8");
        });
        YSFSwizzleSelectorReturningObject("GetHkeDeviceIdentifierV7WithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v7");
        });

        // ---- 越狱 / 签名痕迹 ----
        const char *noSels[] = {
            "isJailBreak", "hasJailbreakFile", "hasMobileSubstrate", "isRooted",
            "p_isJailBreak1", "p_isJailBreak2", "isJailBreakWithPtrace:",
            "hasCydia", "isDeviceJailbreak", "checkJailBreak",
        };
        for (size_t i = 0; i < sizeof(noSels) / sizeof(noSels[0]); i++) {
            YSFSwizzleSelectorReturningNO(noSels[i]);
        }

        // authorityWithJailBreakFlag: 会去读代码签名 authority,
        // TrollStore/TrollFools 重签后这里会露馅 —— 直接返回 nil。
        YSFSwizzleSelectorReturningObject("authorityWithJailBreakFlag:", ^{
            return (id)nil;
        });
    }
}
