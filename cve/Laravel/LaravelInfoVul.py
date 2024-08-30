#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfoSuc,OutPrintInfo
from pub.com.reqset import ReqSet
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("DocCms", '开始检测Laravel敏感信息泄漏...')
        self.run(url)
        self.run2(url)

        if not self.batch:
            OutPrintInfo("DocCms", 'Laravel敏感信息泄漏检测结束')