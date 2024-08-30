#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class JumpServerInfoScan:

    def run(self, urls):
        url = urls + '/api/v1/terminal/sessions/'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            if "account_id" in response.text:
                OutPrintInfoSuc("JumpServer", f'存在JumpServer未授权 {urls}')
                if self.batch:
                    with open("./result/jumpserver_wsq.txt","a") as w:
                        w.write(f"{urls}\n")
            else:
                if not self.batch:
                    OutPrintInfo("JumpServer", '不存在JumpServer未授权漏洞')
        except Exception:
            if not self.batch:
                OutPrintInfo("JumpServer", '目标访问失败')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JumpServer", '开始执行JumpServer未授权漏洞检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("JumpServer", 'JumpServer漏洞检测执行结束')