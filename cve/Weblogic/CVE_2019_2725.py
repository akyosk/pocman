#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2019_2725:
    def get_url(self,input_url,dir):
        try:
            url = input_url + dir
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            # if "AsyncResponseService" in req.text:
            if req.status_code == 200:
                OutPrintInfoSuc("Weblogic", f'目标存在CVE-2019-2725漏洞: {url}')
                if self.batch:
                    OutPutFile("weblogic_2019_2725.txt",f'目标存在CVE-2019-2725漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Weblogic", f'目标不存在CVE-2019-2725漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Weblogic",f'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Weblogic", '开始检测CVE-2019-2725...')
        dir = [
            "/_async/AsyncResponseService/",
            "/_async/AsyncResponseServiceJms/",
            "/_async/AsyncResponseServiceHttps/",
            "/_async/AsyncResponseServiceSoap12/",
            "/_async/AsyncResponseServiceSoap12Jms/",
            "/_async/AsyncResponseServiceSoap12Https",

        ]
        for i in dir:
            self.get_url(url,i)
        if not self.batch:
            OutPrintInfo("Weblogic", 'CVE-2019-2725检测结束')
