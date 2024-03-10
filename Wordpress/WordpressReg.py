#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class WordpressRegScan:
    def run(self, urls):
        try:
            url = urls + '/wp-login.php?action=register'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "Eror" not in response.text and response.status_code == 200 and "Error" not in response.text and "错误" not in response.text and "錯誤" not in response.text:
                OutPrintInfoSuc("Wordpress", f"Wordpress注册开启 {url}")
                if self.batch:
                    OutPutFile("wordpress_reg_open.txt",f"Wordpress注册开启 {url}")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Wordpress", '不存在Wordpress注册开启')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Wordpress", '目标请求出错')
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
            OutPrintInfo("Wordpress", '开始检测Wordpress注册开启漏洞...')
        self.run(url)

        if not self.batch:
            OutPrintInfo("Wordpress", 'Wordpress注册开启检测结束')