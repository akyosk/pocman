#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet

urllib3.disable_warnings()
class PMASetupScan:
    def run(self, urls):
        try:
            url = urls + '/setup/index.php'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and response.url == url and "Language" in response.text:
                OutPrintInfoSuc("PhpMyAdmin", f"存在数据库setup路径 {url}")
                if self.batch:
                    with open("./result/pma_setup.txt", "a") as w:
                        w.write(f"{url}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("PHPMyAdmin", '不存在数据库setup路径')
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
            OutPrintInfo("PHPMyAdmin", '开始检测数据库setup路径...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("PHPMyAdmin", '数据库setup路径检测结束')