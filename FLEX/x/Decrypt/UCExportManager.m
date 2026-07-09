#import "UCExportManager.h"
#import "CDZipWriter.h"
#import "FLEXActivityViewController.h"

@interface FLEXHTTPTransaction : NSObject
@property (nonatomic, readonly) NSString *requestID;
@property (nonatomic) NSURLResponse *response;
@property (nonatomic, readonly) NSURLRequest *request;
@property (nonatomic, copy) NSString *requestMechanism;
@property (nonatomic, readonly) NSData *cachedRequestBody;
@property (nonatomic, readonly) NSString *copyString;
@end

@interface FLEXNetworkRecorder : NSObject
+ (FLEXNetworkRecorder *)defaultRecorder;
- (NSData *)cachedResponseBodyForTransaction:(FLEXHTTPTransaction *)transaction;
@end

@implementation UCExportManager

+ (NSString *)tempExportDir {
    NSString *tmp = NSTemporaryDirectory();
    NSString *dir = [tmp stringByAppendingPathComponent:@"FLEXExport"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir]) {
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return dir;
}

+ (void)exportItems:(NSArray<NSDictionary *> *)items
          tableName:(NSString *)tableName
 fromViewController:(UIViewController *)vc
         completion:(void (^)(BOOL))completion {

    if (items.count == 0) {
        if (completion) completion(NO);
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *folderName = [tableName stringByReplacingOccurrencesOfString:@"_" withString:@""];
        NSString *exportDir = [[self tempExportDir] stringByAppendingPathComponent:folderName];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:exportDir error:nil];
        [fm createDirectoryAtPath:exportDir withIntermediateDirectories:YES attributes:nil error:nil];

        NSMutableArray<NSString *> *fileNames = [NSMutableArray array];

        for (NSInteger i = 0; i < (NSInteger)items.count; i++) {
            NSDictionary *item = items[i];
            NSString *text = item[@"longText"] ?: @"";
            NSString *ts = item[@"timestamp"] ?: [NSString stringWithFormat:@"%ld", (long)i];
            NSString *safe = [[ts stringByReplacingOccurrencesOfString:@":" withString:@"-"]
                              stringByReplacingOccurrencesOfString:@"/" withString:@"-"];
            NSString *filename = [NSString stringWithFormat:@"%02ld_%@.txt", (long)(i + 1), safe];
            NSString *filePath = [exportDir stringByAppendingPathComponent:filename];
            [text writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [fileNames addObject:filename];
        }

        NSString *zipName = [NSString stringWithFormat:@"FLEX_%@_%lu条.zip", tableName, (unsigned long)items.count];
        NSString *zipPath = [exportDir stringByAppendingPathComponent:zipName];

        NSError *err = nil;
        BOOL ok = [CDZipWriter createZipAtPath:zipPath rootDir:exportDir files:fileNames progress:nil error:&err];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                [self shareFileAtPath:zipPath fromViewController:vc];
            }
            if (completion) completion(ok);
        });
    });
}

+ (void)exportNetworkTransactions:(NSArray *)transactions
               fromViewController:(UIViewController *)vc
                       completion:(void (^)(BOOL))completion {

    if (transactions.count == 0) {
        if (completion) completion(NO);
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *exportDir = [[self tempExportDir] stringByAppendingPathComponent:@"network"];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:exportDir error:nil];
        [fm createDirectoryAtPath:exportDir withIntermediateDirectories:YES attributes:nil error:nil];

        NSMutableArray<NSString *> *fileNames = [NSMutableArray array];

        for (NSInteger i = 0; i < (NSInteger)transactions.count; i++) {
            FLEXHTTPTransaction *tx = transactions[i];
            NSMutableString *content = [NSMutableString string];

            [content appendFormat:@"请求URL: %@\n", tx.request.URL.absoluteString ?: @"(nil)"];
            [content appendFormat:@"请求方法: %@\n", tx.request.HTTPMethod ?: @"GET"];
            [content appendFormat:@"请求机制: %@\n", tx.requestMechanism ?: @"NSURLSession"];
            [content appendFormat:@"请求ID: %@\n", tx.requestID ?: @"-"];

            if (tx.request.allHTTPHeaderFields.count > 0) {
                [content appendString:@"\n--- 请求头 ---\n"];
                for (NSString *key in tx.request.allHTTPHeaderFields) {
                    [content appendFormat:@"%@: %@\n", key, tx.request.allHTTPHeaderFields[key]];
                }
            }

            if (tx.cachedRequestBody.length > 0) {
                [content appendString:@"\n--- 请求体 ---\n"];
                NSString *body = [[NSString alloc] initWithData:tx.cachedRequestBody encoding:NSUTF8StringEncoding];
                if (body) {
                    [content appendString:body];
                } else {
                    [content appendFormat:@"[二进制 %lu 字节]", (unsigned long)tx.cachedRequestBody.length];
                }
                [content appendString:@"\n"];
            }

            if (tx.response) {
                NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)tx.response;
                [content appendFormat:@"\n--- 响应 ---\n"];
                [content appendFormat:@"状态码: %ld\n", (long)httpResp.statusCode];
                if (httpResp.allHeaderFields.count > 0) {
                    [content appendString:@"响应头:\n"];
                    for (NSString *key in httpResp.allHeaderFields) {
                        [content appendFormat:@"  %@: %@\n", key, httpResp.allHeaderFields[key]];
                    }
                }
            }

            NSData *responseBody = [[FLEXNetworkRecorder defaultRecorder] cachedResponseBodyForTransaction:tx];
            if (responseBody.length > 0) {
                [content appendString:@"\n--- 响应体 ---\n"];
                NSString *body = [[NSString alloc] initWithData:responseBody encoding:NSUTF8StringEncoding];
                if (body) {
                    [content appendString:body];
                } else {
                    [content appendFormat:@"[二进制 %lu 字节]", (unsigned long)responseBody.length];
                }
                [content appendString:@"\n"];
            }

            NSString *urlPart = tx.request.URL.host ?: @"unknown";
            NSString *filename = [NSString stringWithFormat:@"%02ld_%@.txt", (long)(i + 1), urlPart];
            NSString *filePath = [exportDir stringByAppendingPathComponent:filename];

            [content writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [fileNames addObject:filename];
        }

        NSString *zipName = [NSString stringWithFormat:@"FLEX_network_%lu条.zip", (unsigned long)transactions.count];
        NSString *zipPath = [exportDir stringByAppendingPathComponent:zipName];

        NSError *err = nil;
        BOOL ok = [CDZipWriter createZipAtPath:zipPath rootDir:exportDir files:fileNames progress:nil error:&err];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                [self shareFileAtPath:zipPath fromViewController:vc];
            }
            if (completion) completion(ok);
        });
    });
}

+ (void)shareFileAtPath:(NSString *)filePath fromViewController:(UIViewController *)vc {
    NSURL *url = [NSURL fileURLWithPath:filePath];
    UIActivityViewController *avc = [[UIActivityViewController alloc]
        initWithActivityItems:@[url] applicationActivities:nil];

    if (avc.popoverPresentationController) {
        avc.popoverPresentationController.barButtonItem = vc.navigationItem.rightBarButtonItems.lastObject;
    }

    [vc presentViewController:avc animated:YES completion:nil];
}

@end
