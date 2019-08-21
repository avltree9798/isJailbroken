//
//  ViewController.m
//  isJailbroken
//
//  Created by Anthony Viriya on 8/21/19.
//  Copyright © 2019 AVL. All rights reserved.
//

#import "ViewController.h"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    if(isJb()){
        NSLog(@"Jailbroken");
    }else{
        NSLog(@"Not Jailbroken");
    }
}


@end
