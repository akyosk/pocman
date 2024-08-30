#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class PBSqlScan:

    def run(self, urls):
        try:
            url = urls + "/?youc'"
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "syntax" in response.text:
                OutPrintInfoSuc("PBootCms", f'存在SQL注入 {url}')
                if self.batch:
                    with open("./result/pbootcms_sql.txt", "a") as w:
                        w.write(f"{url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("PBootCms", '不存在存在SQL注入')

        except Exception:
            if not self.batch:
                OutPrintInfo("Ruoyi", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("PBootCms", '开始检测SQL注入...')
        self.run(url)

        if not self.batch:
            OutPrintInfo("PBootCms", 'SQL注入检测结束')