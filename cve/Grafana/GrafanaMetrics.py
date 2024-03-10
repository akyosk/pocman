#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()

class GrafanaMetricsScan:
    def run(self, urls):
        url = urls + '/metrics'
        try:
            response = requests.get(url, headers=self.header, verify=self.ssl, proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfoSuc("Grafana",f'指标集群地址:{url}')
                if self.batch:
                    OutPutFile("grafana_jiqun.txt",f'指标集群地址:{url}')
        except Exception:
            OutPrintInfo("Grafana","目标请求出错")

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.header = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.header = req["header"]
        if not self.batch:
            OutPrintInfo("Grafana",'开始执行Grafana指标集群检测')
        self.run(url)

        if not self.batch:
            OutPrintInfo("Grafana",'Grafana指标集群检测结束')