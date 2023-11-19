#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Author: coleak
version: 1.2
'''
from cve.WebInfoScan.dirpro_main.script.end import _end
from cve.WebInfoScan.dirpro_main.script.start import _start
class Dirpro:
    def main(self,target):

        print(r'''
      __                                    
     /\ \  __                               
     \_\ \/\_\  _ __   _____   _ __   ___   
     /'_` \/\ \/\`'__\/\ '__`\/\`'__\/ __`\ 
    /\ \L\ \ \ \ \ \/ \ \ \L\ \ \ \//\ \L\ \
    \ \___,_\ \_\ \_\  \ \ ,__/\ \_\\ \____/
     \/__,_ /\/_/\/_/   \ \ \/  \/_/ \/___/ 
                         \ \_\              
                          \/_/      
    ''')
        # if not args.f:
        url = target[0].strip('/ ')
        # rooturl = args.u.strip('/')
        (time1,ret)=_start(target,url)
        _end(url,time1,ret)
        # else:
        #     urlfile=open(args.f, 'r')
        #     urls = urlfile.read().splitlines()
        #     for rooturl in urls:
        #         rooturl = rooturl.strip('/')
        #         (time1,ret) = __start(args, rooturl)
        #         __end(rooturl,time1,ret)