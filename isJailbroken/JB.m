//
//  JB.m
//  isJailbroken
//
//  Created by Anthony Viriya on 8/21/19.
//  Copyright © 2019 AVL. All rights reserved.
//  Reference : https://www.theiphonewiki.com/wiki/Bypassing_Jailbreak_Detection
//

#import "JB.h"

@implementation JB

#define A(c)            (c) - 0x19
#define HIDE_STR(str)   do { char *p = str;  while (*p) *p++ -= 0x19; } while (0)
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

CFRunLoopSourceRef gSocketSource;
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

// Preventing libobjc hooked, strstr implementation
const char* tuyul(const char* X, const char* Y)
{
    if (*Y == '\0')
        return X;

    for (int i = 0; i < strlen(X); i++)
    {
        if (*(X + i) == *Y)
        {
            char* ptr = tuyul(X + i + 1, Y + 1);
            return (ptr) ? ptr - 1 : NULL;
        }
    }

    return NULL;
}

BOOL isJb()
{
    //Check cydia URL
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.avl.com"]])
    {
        return YES;
    }
    NSArray* checks = [[NSArray alloc]initWithObjects:[NSString  stringWithFormat:@"/%@%@%@%@%@%@/%@%@%@%@%@",@"A",@"pp",@"li",@"ca",@"ti",@"on",@"Cy",@"di",@"a.",@"ap",@"p"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@", @"Libr",@"ary/Mo",@"bileSubstra",@"te/MobileSubs",@"trate.dylib"],
                       [NSString stringWithFormat:@"/%@%@%@", @"bi",@"n/b",@"ash"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@", @"us", @"r/sb",@"in", @"s", @"shd"],
                       [NSString stringWithFormat:@"/%@%@%@", @"et",@"c/a",@"pt/"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@", @"us", @"r/b",@"in", @"s", @"sh"],
                       [NSString stringWithFormat:@"/%@%@%@%@", @"private/va",@"r/l",@"ib",@"/apt/"],
                       [NSString stringWithFormat:@"/%@%@%@%@", @"private/va",@"r/l",@"ib/c",@"ydia/"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@", @"private/va",@"r/t",@"mp/c",@"ydia.",@"log"],
                       [NSString stringWithFormat:@"/%@%@%@%@", @"va",@"r/l",@"ib/c",@"ydia/"],
                       [NSString stringWithFormat:@"/%@%@%@", @"priv",@"ate/etc/dpkg/",@"origins/debian"],
                       [NSString stringWithFormat:@"/%@%@%@", @"b",@"in/",@"sh"],
                       [NSString stringWithFormat:@"/%@%@", @"private/etc/a",@"pt"],
                       [NSString stringWithFormat:@"/%@%@%@", @"etc/s",@"sh/s",@"shd_config"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@", @"priva",@"te/et",@"c/s",@"sh/s",@"shd_config"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@%@",@"pri",@"vatr/va",@"r/mobil",@"eLibrar",@"y/SBSe",@"tt",@"ings",@"Themes/"],
                       [NSString stringWithFormat:@"/%@%@%@%@", @"pri",@"vate/va",@"r/s",@"tash"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"us", @"r/l",@"ibe", @"xe", @"c/sft", @"p-ser",@"ver"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@", @"us", @"r/l",@"ibe", @"xe", @"c/cy", @"dia/"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"us", @"r/sb",@"in/", @"fri", @"da-", @"se",@"rver"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"us", @"r/b",@"in/", @"c", @"ycr", @"i",@"pt"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"us", @"r/loc",@"al/bin/", @"c", @"ycr", @"i",@"pt"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"us", @"r/lib",@"/lib", @"cy", @"cr", @"i",@"pt.dylib"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@%@",@"Sy",@"stem/Lib",@"rary/Laun",@"chDae",@"mons/com.saur",@"ik.Cy",@"@dia.Star",@"tup.plist"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@%@",@"Sy",@"stem/Lib",@"rary/Laun",@"chDae",@"mons/com.ik",@"ey.bbo",@"@t.",@"plist"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@%@",@"Libr",@"ary/Mobil",@"eSubstrate/Dy",@"namic",@"Libraries/",@"Veen",@"cy.",@"plist"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@%@",@"Libr",@"ary/Mobil",@"eSubstrate/Dy",@"namic",@"Libraries/",@"Live",@"Clock.",@"plist"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@", @"us",@"r/li",@"bexe",@"c/ssh-k",@"eysign"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@", @"us", @"r/l",@"ibe", @"xe", @"c/sftp-", @"server"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"App", @"lic",@"ati", @"ons/", @"bla", @"ckra1n.a", @"pp"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@%@", @"App", @"lic",@"ati", @"ons/", @"Fake", @"Car",@"rier.a", @"pp"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"App", @"lic",@"ati", @"ons/", @"Int", @"elliScre", @"en.app"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"App", @"lic",@"ati", @"ons/", @"Win", @"terBo", @"ard.app"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"App", @"lic",@"ati", @"ons/", @"SB", @"Set", @"tings.app"],
                       [NSString stringWithFormat:@"/%@%@%@%@%@%@%@", @"App", @"lic",@"ati", @"ons/", @"Snoop-it", @" Config.a", @"pp"],
                       [NSString stringWithFormat:@"/%@%@%@", @"priv",@"ate/etc/dpkg/",@"origins/debian"],
                       nil];
    //Check installed app
    for(NSString* check in checks)
    {
        if(canOpen(check))
        {
            return YES;
        }
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
        if(sym.st_mode & S_IFLNK)
        {
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
        if(error==nil)
        {
            return YES;
        }
        return NO;
    } @catch (NSException *exception) {
        return NO;
    }
}

char* UNHIDE_STR(char* str){
    do { char *p = str;  while (*p) *p++ += 0x19; } while (0);
    return str;
}

char* decryptString(char* str){
    str = UNHIDE_STR(str);
    str[strlen(str)]='\0';
    return str;
}

BOOL isInjectedWithDynamicLibrary()
{
    int i=0;
    while(true){
        const char *name = _dyld_get_image_name(i++);
        if(name==NULL){
            break;
        }
        if (name != NULL) {
            char cyinjectHide[] = {
                A('c'),
                A('y'),
                A('n'),
                A('j'),
                A('e'),
                A('c'),
                A('t'),
                0
            };
            char libcycriptHide[] = {
                A('l'),
                A('i'),
                A('b'),
                A('c'),
                A('y'),
                A('c'),
                A('r'),
                A('i'),
                A('p'),
                A('t'),
                0
            };
            
            char libfridaHide[] = {
                A('F'),
                A('r'),
                A('i'),
                A('d'),
                A('a'),
                A('G'),
                A('a'),
                A('d'),
                A('g'),
                A('e'),
                A('t'),
                0
            };
            char zzzzLibertyDylibHide[] = {
                A('z'),
                A('z'),
                A('z'),
                A('z'),
                A('L'),
                A('i'),
                A('b'),
                A('e'),
                A('r'),
                A('t'),
                A('y'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            char sslkillswitch2dylib[] = {
                A('S'),
                A('S'),
                A('L'),
                A('K'),
                A('i'),
                A('l'),
                A('l'),
                A('S'),
                A('w'),
                A('i'),
                A('t'),
                A('c'),
                A('h'),
                A('2'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char zeroshadowdylib[] = {
                A('0'),
                A('S'),
                A('h'),
                A('a'),
                A('d'),
                A('o'),
                A('w'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char mobilesubstratedylib[] = {
                A('M'),
                A('o'),
                A('b'),
                A('i'),
                A('l'),
                A('e'),
                A('S'),
                A('u'),
                A('b'),
                A('s'),
                A('t'),
                A('r'),
                A('a'),
                A('t'),
                A('e'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };

            //For frida-*
            char fridadylib[] = {
                A('f'),
                A('r'),
                A('i'),
                A('d'),
                A('a'),
                0
            };
            
            char libsparkapplistdylib[] = {
                A('l'),
                A('i'),
                A('b'),
                A('s'),
                A('p'),
                A('a'),
                A('r'),
                A('k'),
                A('a'),
                A('p'),
                A('p'),
                A('l'),
                A('i'),
                A('s'),
                A('t'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            if (tuyul(name, decryptString(mobilesubstratedylib)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(fridadylib)) != NULL){
                return YES;
            }
            if(tuyul(name, decryptString(libsparkapplistdylib)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(cyinjectHide)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(libcycriptHide)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(libfridaHide)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(zzzzLibertyDylibHide)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(sslkillswitch2dylib)) != NULL){
                return YES;
            }
            if (tuyul(name, decryptString(zeroshadowdylib)) != NULL){
                return YES;
            }
        }
    }
    return NO;
}

// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
// Thanks to https://developer.apple.com/library/archive/qa/qa1361/_index.html
BOOL isDebugged()
{
    int junk;
    int mib[4];
    struct kinfo_proc info;
    size_t size;
    info.kp_proc.p_flag = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
}

BOOL isSecure()
{
    return
            isJb() &&
            isInjectedWithDynamicLibrary();
    
}


@end
