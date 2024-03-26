#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()

class Cve_2017_10271:
    def get_url(self,input_url,dir):
        try:
            url = input_url + dir
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "Endpoint" in req.text:
                OutPrintInfoSuc("Weblogic", f'目标存在CVE-2017-10271漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("Weblogic", "可参考https://www.cnblogs.com/pursue-security/p/17029526.html")

                else:
                    OutPutFile("weblogic_2017_10271.txt",f'目标存在CVE-2017-10271漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Weblogic", f'目标不存在CVE-2017-10271漏洞')
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
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Weblogic", '开始检测CVE-2017-10271...')
        dir = [
            "/wls-wsat/CoordinatorPortType",
            "/wls-wsat/RegistrationPortTypeRPC",
            "/wls-wsat/ParticipantPortType",
            "/wls-wsat/RegistrationRequesterPortType",
            "/wls-wsat/CoordinatorPortType11",
            "/wls-wsat/RegistrationPortTypeRPC11",
            "/wls-wsat/ParticipantPortType11",
            "/wls-wsat/RegistrationRequesterPortType11",
        ]
        for i in dir:
            self.get_url(url,i)
        if not self.batch:
            OutPrintInfo("Weblogic", 'CVE-2017-10271检测结束')
