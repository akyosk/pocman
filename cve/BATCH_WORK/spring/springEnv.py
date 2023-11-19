#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests, urllib3
from libs.public.outprint import OutPrintInfo

urllib3.disable_warnings()
class SpringEnv:
    def env(self, base_url, proxies):
        headr = {
            "User-Agent": self.headers,
        }
        url = base_url + "/env"
        try:
            req = requests.get(url, headers=headr,timeout=self.timeout, verify=self.ssl, proxies=proxies)
            if "password" in req.text:
                if self.flag:
                    if "******" not in req.text and url == req.url:
                        OutPrintInfo("Spring", f"存在Spring-Env漏洞 URL {url}")
                        with open("./result/springEnvTrue.txt", "a") as w:
                            w.write(f"{url}\n")
                else:
                    OutPrintInfo("Spring", f"存在Spring-Env漏洞 URL {url}")
                    with open("./result/springEnv.txt", "a") as w:
                        w.write(f"{url}\n")
            else:
                # OutPrintInfo("Spring", "CVE-2022-22965漏洞不存在或者已经被利用,shell地址自行扫描")
                pass
        except Exception as e:
            # OutPrintInfo("Spring", e)
            pass
    def env2(self, base_url, proxies):
        headr = {
            "User-Agent": self.headers,
        }
        url = base_url + "/actuator/env"
        try:
            req = requests.get(url, headers=headr,timeout=self.timeout, verify=self.ssl, proxies=proxies)
            if "password" in req.text:
                if self.flag:
                    if "******" not in req.text and url == req.url:
                        OutPrintInfo("Spring", f"存在Spring-Env漏洞 URL {url}")
                        with open("./result/springEnvTrue.txt", "a") as w:
                            w.write(f"{url}\n")
                else:
                    OutPrintInfo("Spring", f"存在Spring-Env漏洞 URL {url}")
                    with open("./result/springEnv.txt", "a") as w:
                        w.write(f"{url}\n")
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
        self.flag = target[5]
        proxys = {"http": proxy, "https": proxy}
        self.env(url, proxys)
        self.env2(url, proxys)