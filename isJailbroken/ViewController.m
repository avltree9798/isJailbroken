//
//  ViewController.m
//  isJailbroken
//
//  Created by Anthony Viriya on 8/21/19.
//  Copyright © 2019 AVL. All rights reserved.
//

#import "ViewController.h"


@interface ViewController ()
@property NSThread* evtThread;
@property (weak, nonatomic) IBOutlet UILabel *securityCheckStatus;
@property (weak, nonatomic) IBOutlet UILabel *appStoreStatus;
@property (weak, nonatomic) IBOutlet UILabel *debugStatus;
@property (weak, nonatomic) IBOutlet UILabel *dylibStatus;
@property (weak, nonatomic) IBOutlet UILabel *coreJbStatus;
@property (weak, nonatomic) IBOutlet UILabel *systemLabel;
@end

@implementation ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    BOOL securityCheckResult = isSecurityCheckNotPassed();
    BOOL appStoreResult = isFromAppStore();
    BOOL debugResult = isDebugged();
    BOOL dylibResult = isInjectedWithDynamicLibrary();
    BOOL coreJbResult = isJb();
    self.securityCheckStatus.text = securityCheckResult?@"TRUE":@"FALSE";
    self.appStoreStatus.text = appStoreResult?@"TRUE":@"FALSE";
    self.debugStatus.text = debugResult?@"TRUE":@"FALSE";
    self.dylibStatus.text = dylibResult?@"TRUE":@"FALSE";
    self.coreJbStatus.text = coreJbResult?@"TRUE":@"FALSE";
    struct utsname systemInfo;
    uname(&systemInfo);
    NSMutableString *str = [[NSMutableString alloc] initWithFormat:@"%@\n%@", [[NSString alloc] initWithUTF8String:systemInfo.machine], [[NSString alloc] initWithUTF8String:systemInfo.version]];
    self.systemLabel.text = str;
    self.systemLabel.lineBreakMode = NSLineBreakByWordWrapping;
    self.systemLabel.numberOfLines = 0;
    NSArray *texts = [[NSArray alloc] initWithObjects:self.appStoreStatus, self.debugStatus, self.coreJbStatus,self.dylibStatus, nil];
    for(UILabel* lbl in texts){
        if([[lbl text] isEqualToString:@"TRUE"]){
            lbl.textColor = UIColor.redColor;
        }else{
            lbl.textColor = UIColor.blueColor;
        }
    }
    if([[self.securityCheckStatus text] isEqualToString:@"TRUE"]){
        self.securityCheckStatus.textColor = UIColor.greenColor;
    }else{
        self.securityCheckStatus.textColor = UIColor.redColor;
    }
    
}


@end
