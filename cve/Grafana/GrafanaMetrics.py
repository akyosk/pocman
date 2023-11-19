#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()

class GrafanaMetricsScan:

    def run(self, urls):
        urllib3.disable_warnings()
        url = urls + '/metrics'
        response = requests.get(url, headers=self.header, verify=self.ssl, proxies=self.proxy)

        OutPrintInfo("Grafana",f"响应:\n{response.text}")
        OutPrintInfo("Grafana",f'检测地址:[b bright_red]{url}[/b bright_red]')

    def main(self, target):
        OutPrintInfo("Grafana",'开始执行Grafana指标集群检测')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]

        req = ReqSet(header=header, proxy=proxy)
        self.header = req["header"]
        self.proxy = req["proxy"]

        self.run(url)


        OutPrintInfo("Grafana",'Grafana指标集群检测结束')