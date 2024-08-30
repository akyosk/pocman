# -*- coding: utf-8 -*-
from cve.Shiro.ShiroScan_master.moule.main import scripts
class ShiroScan:
    def main(self,target):
        banner = '''
         ____  _     _          ____                  
        / ___|| |__ (_)_ __ ___/ ___|  ___ __ _ _ __  
        \___ \| '_ \| | '__/ _ \___ \ / __/ _` | '_ \ 
         ___) | | | | | | | (_) |__) | (_| (_| | | | |
        |____/|_| |_|_|_|  \___/____/ \___\__,_|_| |_|
                                                By 斯文
        '''

        print(banner)
        print('Welcome To Shiro反序列化 RCE ! ')
        url = target["url"].strip('/ ')
        command = target["cmd"]
        scripts(url, command)

    
