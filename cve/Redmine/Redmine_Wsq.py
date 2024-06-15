#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Redmine", '开始执行Redmine未授权漏洞检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Redmine", 'Redmine未授权漏洞检测执行结束')


