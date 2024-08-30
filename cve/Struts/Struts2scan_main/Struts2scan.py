#!/usr/bin/env python
# coding=utf-8

# from gevent import monkey;monkey.patch_all()#并发,要放最前面
from gevent.pool import Pool
import gevent
import re
import urllib
import urllib3
urllib3.disable_warnings()
from cve.Struts.Struts2scan_main.module.proxy import proxies
from cve.Struts.Struts2scan_main.module.color import color
from cve.Struts.Struts2scan_main.payloads.s2_001 import s2_001,s2_001_exp
from cve.Struts.Struts2scan_main.payloads.s2_005 import s2_005,s2_005_exp
from cve.Struts.Struts2scan_main.payloads.s2_007 import s2_007,s2_007_exp
from cve.Struts.Struts2scan_main.payloads.s2_008 import s2_008,s2_008_exp
from cve.Struts.Struts2scan_main.payloads.s2_009 import s2_009,s2_009_exp
from cve.Struts.Struts2scan_main.payloads.s2_013 import s2_013,s2_013_exp
from cve.Struts.Struts2scan_main.payloads.s2_015 import s2_015,s2_015_exp
from cve.Struts.Struts2scan_main.payloads.s2_032 import s2_032,s2_032_exp
from cve.Struts.Struts2scan_main.payloads.s2_045 import s2_045,s2_045_exp
from cve.Struts.Struts2scan_main.payloads.s2_046 import s2_046,s2_046_exp
from cve.Struts.Struts2scan_main.payloads.s2_048 import s2_048,s2_048_exp
from cve.Struts.Struts2scan_main.payloads.s2_052 import s2_052,s2_052_exp
from cve.Struts.Struts2scan_main.payloads.s2_053 import s2_053,s2_053_exp
from cve.Struts.Struts2scan_main.payloads.s2_057 import s2_057,s2_057_exp
from cve.Struts.Struts2scan_main.payloads.s2_059 import s2_059,s2_059_exp
from cve.Struts.Struts2scan_main.payloads.s2_061 import s2_061,s2_061_exp


class Struts2Scaner:

    def RunScan(self,targeturl):
        poclist = [
            's2_001("{0}")'.format(targeturl),
            's2_005("{0}")'.format(targeturl),
            's2_008("{0}")'.format(targeturl),
            's2_009("{0}")'.format(targeturl),
            's2_007("{0}")'.format(targeturl),
            's2_013("{0}")'.format(targeturl),
            's2_015("{0}")'.format(targeturl),
            's2_032("{0}")'.format(targeturl),
            's2_045("{0}")'.format(targeturl),
            's2_046("{0}")'.format(targeturl),
            's2_048("{0}")'.format(targeturl),
            's2_052("{0}")'.format(targeturl),
            's2_053("{0}")'.format(targeturl),
            's2_057("{0}")'.format(targeturl),
            's2_059("{0}")'.format(targeturl),
            's2_061("{0}")'.format(targeturl),
        ]
        # print(poclist)
        def pocexec(pocstr):
            exec(pocstr)
            gevent.sleep(0)
        try:
            pool = Pool(10)
            threads = [pool.spawn(pocexec, item) for item in poclist]
            gevent.joinall(threads)
        except:
            exit()



    def SetProxy(self,Proxy):
        scheme = urllib.parse.urlparse(Proxy).scheme
        proxies.update({'http': Proxy,'https': Proxy})




    def main(self,target):
        print(color.cyan(
            "  _____ _              _       ___\r\n" +
            " / ____| |            | |     |__ \\\r\n" +
            "| (___ | |_ _ __ _   _| |_ ___   ) |___  ___ __ _ _ __\r\n" +
            " \___ \| __| '__| | | | __/ __| / // __|/ __/ _` | '_ \\ \r\n") +
color.magenta(" ____) | |_| |  | |_| | |_\__ \/ /_\__ \ (_| (_| | | | |\r\n" +
            "|_____/ \__|_|   \__,_|\__|___/____|___/\___\__,_|_| |_|\r\n" +
            "V1.0                                        by Abs1n7he\r"))
        # figlet -f big Struts2scan
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        if proxy:
            if re.findall('[a-zA-z]+://[^\s]{1,}(:{0,1})(\d*)', proxy):
                self.SetProxy(proxy)
                print(color.red("[+]Proxy:" + proxies['http']))
            else:
                print(color.red("[!]代理格式错误"))
                exit()
        if url:
            if url.find('http')==-1:
                print(color.red("[!]url无法识别"))
                exit()
            else:
                self.RunScan(url)
        else:
            exit()





