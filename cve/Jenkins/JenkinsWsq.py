#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class JenkinsWsqScan:
    def run2(self, urls):
        url = urls + '/script'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfoSuc("Jenkins", f'存在Jenkins未授权{url}')

                if self.batch:
                    OutPutFile("jenkins_wsq.txt", f"存在Jenkins未授权{url}")
            else:
                if not self.batch:
                    OutPrintInfo("Jenkins", '不存在Jenkins未授权')
        except Exception:
            if not self.batch:
                OutPrintInfo("Jenkins", '目标访问出错')
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
            OutPrintInfo("Jenkins", '开始执行Jenkins未授权漏洞检测')
        self.run2(url)
        if not self.batch:
            OutPrintInfo("Jenkins", 'Jenkins漏洞检测执行结束')