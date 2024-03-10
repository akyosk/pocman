#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfoSuc,OutPrintInfo
from libs.reqset import ReqSet
urllib3.disable_warnings()

class LaravelInfoScan:
    def run(self, urls):
        try:
            url = urls + '/index/xvcbvvfdbgnhgbgin.html'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "DB_HOST" in response.text or "REDIS_" in response.text:
                OutPrintInfoSuc("Laravel", f"存在敏感信息 {url}")
                if self.batch:
                    with open("./result/laravel_info_vuls.txt", "a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("DocCms", '不存在Laravel敏感信息泄漏')

        except Exception:
            if not self.batch:
                OutPrintInfo("DocCms", '目标请求出错')
    def run2(self, urls):
        try:
            url = urls + '/.env'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "DB_HOST" in response.text or "REDIS_" in response.text:
                OutPrintInfoSuc("Laravel", f"存在敏感信息 {url}")
                if self.batch:
                    with open("./result/laravel_info_vuls.txt", "a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("DocCms", '不存在Laravel敏感信息泄漏')

        except Exception:
            if not self.batch:
                OutPrintInfo("DocCms", '目标请求出错')
    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("DocCms", '开始检测Laravel敏感信息泄漏...')
        self.run(url)
        self.run2(url)

        if not self.batch:
            OutPrintInfo("DocCms", 'Laravel敏感信息泄漏检测结束')