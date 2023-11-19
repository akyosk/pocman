#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class PBSqlScan:

    def run(self, urls):
        try:
            url = urls + "/?youc'"
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "syntax" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("PBootCms", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/pbootCmsSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass

    def main(self, target):
        # OutPrintInfo("DocCms", '开始检测SQL注入...')
        url = target[0].strip('/ ')
        self.ssl = target[1]
        header = target[2]
        proxy = target[3]
        self.timeout = int(target[4])
        req = ReqSet(header=header)
        self.headers = req["header"]
        self.proxy = {"http":proxy,"https":proxy}

        self.run(url)


        # OutPrintInfo("DocCms", 'SQL注入检测结束')