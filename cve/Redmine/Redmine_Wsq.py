#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class Redmine_Wsq_Scan:
    def run(self, urls):
        url = urls + '/attachments/'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfo("Redmine", f'存在Redmine未授权漏洞:{url}')
                if self.batch:
                    OutPutFile("redmine_wsq.txt",f'存在Redmine未授权漏洞:{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Redmine", '不存在Redmine未授权漏洞')

        except Exception:
            if not self.batch:
                OutPrintInfo("Redmine", '目标请求出错')

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
            OutPrintInfo("Redmine", '开始执行Redmine未授权漏洞检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Redmine", 'Redmine未授权漏洞检测执行结束')


