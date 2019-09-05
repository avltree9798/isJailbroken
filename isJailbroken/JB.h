//
//  JB.h
//  isJailbroken
//
//  Created by Anthony Viriya on 8/21/19.
//  Copyright © 2019 AVL. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>

NS_ASSUME_NONNULL_BEGIN

@interface JB : NSObject
BOOL isJb();
BOOL isCycripted();
BOOL isSecure();
BOOL isDebugged();
@end

NS_ASSUME_NONNULL_END
