#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet

urllib3.disable_warnings()
class PhpMyAdminPMAScan:
    def run(self, urls):
        try:
            url = urls + '/pma'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if response.status_code == 200 and "phpmyadmin" in response.text:
                OutPrintInfoSuc("PHPMyAdmin", f"存在未授权 {url}")
                if self.batch:
                    with open("./result/pma_wsq.txt", "a") as w:
                        w.write(f"{url}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("PHPMyAdmin", '不存在未授权')
                return False

        except Exception:
            if not self.batch:
                OutPrintInfo("PHPMyAdmin", '目标请求出错')
            return False


    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("PHPMyAdmin", '开始检测未授权...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("PHPMyAdmin", '未授权检测结束')