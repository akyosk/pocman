#!/usr/bin/env python
# coding=utf-8
import base64
import urllib
import requests
import urllib3
urllib3.disable_warnings()
from cve.Struts.Struts2scan_main.module.proxy import proxies
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout
from requests.exceptions import Timeout
from cve.Struts.Struts2scan_main.payloads.s2_045_1 import s2_045_1,s2_045_1_exp
from cve.Struts.Struts2scan_main.payloads.s2_045_2 import s2_045_2,s2_045_2_exp
from cve.Struts.Struts2scan_main.payloads.s2_045_3 import s2_045_3,s2_045_3_exp

def s2_045(url):
    print("[*] 开始检测S2-045")
    if s2_045_1(url):
        pass
    elif s2_045_2(url):
        pass
    elif s2_045_3(url):
        pass

def s2_045_exp(url):
    Pno = input("Use payload No(1-3): ")
    if Pno == "1":
        s2_045_1_exp(url)
    elif Pno == "2":
        s2_045_2_exp(url)
    elif Pno == "3":
        s2_045_3_exp(url)
