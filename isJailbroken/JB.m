//
//  JB.m
//  isJailbroken
//
//  Created by Anthony Viriya on 8/21/19.
//  Copyright © 2019 AVL. All rights reserved.
//  Reference : https://www.theiphonewiki.com/wiki/Bypassing_Jailbreak_Detection
//

#import "JB.h"
#import <UIKit/UIKit.h>

@implementation JB

BOOL fileExist(NSString* path)
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL isDirectory = NO;
    if([fileManager fileExistsAtPath:path isDirectory:&isDirectory]){
        return YES;
    }
    return NO;
}

BOOL directoryExist(NSString* path)
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL isDirectory = YES;
    if([fileManager fileExistsAtPath:path isDirectory:&isDirectory]){
        return YES;
    }
    return NO;
}

BOOL canOpen(NSString* path)
{
    FILE *file = fopen([path UTF8String], "r");
    if(file==nil){
        return fileExist(path) || directoryExist(path);
    }
    fclose(file);
    return YES;
}

BOOL isJb()
{
    //Check cydia URL
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.avl.com"]])
    {
        return YES;
    }
    
    //Check installed app
    if(canOpen(@"/Applications/Cydia.app") ||
       canOpen(@"/Library/MobileSubstrate/MobileSubstrate.dylib") ||
       canOpen(@"/bin/bash") ||
       canOpen(@"/usr/sbin/sshd") ||
       canOpen(@"/etc/apt") ||
       canOpen(@"/usr/bin/ssh") ||
       canOpen(@"/private/var/lib/apt") ||
       canOpen(@"/private/var/lib/cydia") ||
       canOpen(@"/private/var/tmp/cydia.log") ||
       canOpen(@"/private/var/lib/cydia"))
    {
        return YES;
    }
    
    //symlink verification
    struct stat sym;
    if(lstat("/Applications", &sym) || lstat("/var/stash/Library/Ringtones", &sym) ||
       lstat("/var/stash/Library/Wallpaper", &sym) ||
       lstat("/var/stash/usr/include", &sym) ||
       lstat("/var/stash/usr/libexec", &sym)  ||
       lstat("/var/stash/usr/share", &sym) ||
       lstat("/var/stash/usr/arm-apple-darwin9", &sym))
    {
        if(sym.st_mode & S_IFLNK){
            return YES;
        }
    }
    
    //Check process forking
    int pid = fork();
    if(!pid)
    {
        exit(1);
    }
    if(pid >= 0)
    {
        return YES;
    }
    
    //Check permission to write to /private
    NSString *path = @"/private/avl.txt";
    NSFileManager *fileManager = [NSFileManager defaultManager];
    @try {
        NSError* error;
        NSString *test = @"AVL was here";
        [test writeToFile:test atomically:NO encoding:NSStringEncodingConversionAllowLossy error:&error];
        [fileManager removeItemAtPath:path error:nil];
        if(error==nil){
            return YES;
        }
        return NO;
    } @catch (NSException *exception) {
        return NO;
    }
}

@end
