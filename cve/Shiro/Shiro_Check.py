#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3,re
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from cve.Shiro.Shiro_Exploit import Shiro_Exp_Scan
from cve.Shiro.Shiro_File_Dump import Shiro_File_Dump_Scan
urllib3.disable_warnings()

class Shiro_Check_Run:
    def checkRe(self,target):

        pattern = re.compile(u'^re(.*?)Me') 
        result  = pattern.search(target)
        if result:
            return True
        else:
            return False
    def get_url(self,url):
        header = {
            'User-agent': self.headers["User-Agent"],
            'Cookie': 'rememberMe=1'
        }

        check_one = "rememberMe"
        check_two = "deleteMe"

        try:
            res = requests.post(url, allow_redirects=False, headers=header, verify=False, timeout=30)
            resHeader = str(res.headers)
            check = self.checkRe(resHeader)

            if check_one in resHeader or check_two in resHeader or check:
                OutPrintInfoSuc("Shiro", f"目标存在Shiro特征: {url}")
                if self.batch:
                    OutPutFile("shiro_check.txt", f'目标存在Shiro特征: {url}')
                return True

            
        except Exception:
            if not self.batch:
                OutPrintInfo("Shiro","目标访问出错")
            


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Shiro", '开始检测Shiro特征...')
        if self.get_url(url):
            if not self.batch:
                OutPrintInfo("Shiro", '检测到Shiro特征,执行Shiro漏洞检测...')
                Shiro_File_Dump_Scan().main(target)
                Shiro_Exp_Scan().main(target)
                OutPrintInfo("Shiro", 'Shiro特征检测结束')
                # attack
            return "shiro"
        if not self.batch:
            OutPrintInfo("Shiro", 'Shiro特征检测结束')


