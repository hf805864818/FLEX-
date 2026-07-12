#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DatabaseManager : NSObject

@property (nonatomic, readonly) NSString *dbPath;

+ (instancetype)sharedManager;

- (void)createTables;
- (void)insertDataIntoTable:(NSString *)table bundleID:(NSString *)bundleID text:(NSString *)text;
- (NSArray<NSString *> *)queryTextsFromTable:(NSString *)table bundleID:(NSString *)bundleID;
- (NSArray<NSString *> *)allBundleIDsFromTable:(NSString *)table;
- (NSArray<NSDictionary *> *)queryAllRecordsFromTable:(NSString *)table limit:(NSInteger)limit;
- (void)clearTable:(NSString *)table;

- (void)insertPointCastleKey:(NSString *)keyHex bundleID:(NSString *)bundleID detail:(NSString *)detail;
- (NSArray<NSDictionary *> *)queryPointCastleKeysForBundleID:(NSString *)bundleID limit:(NSInteger)limit;

- (BOOL)getSwitch:(NSString *)switchName bundleID:(NSString *)bundleID defaultValue:(BOOL)defaultValue;
- (void)setSwitch:(NSString *)switchName bundleID:(NSString *)bundleID value:(BOOL)value;

- (BOOL)isSSLEnabledForBundle:(NSString *)bundleID;
- (BOOL)isCryptoCaptureEnabledForBundle:(NSString *)bundleID;
- (BOOL)isDigestCaptureEnabledForBundle:(NSString *)bundleID;
- (BOOL)isHMACCaptureEnabledForBundle:(NSString *)bundleID;

- (void)insertLogText:(NSString *)logText;
- (NSArray<NSString *> *)queryLogs:(NSInteger)limit;

@end

NS_ASSUME_NONNULL_END
