#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3

urllib3.disable_warnings()


class ReqSet:
    def __init__(self, **kwargs):
        self.__kwargs = kwargs
        self.__headers,self.__proxies = self.__run()

    def __proxy(self, target):
        proxy = target
        proxies = self.__check(proxy)
        return proxies

    def __check(self, proxy):
        if proxy:
            from pub.com.outprint import OutPrintInfo
            if '://' in proxy:
                proxy = proxy.split('://')[-1]
            proxies = {
                "http": "http://%(proxy)s/" % {'proxy': proxy.strip("/ ")},
                "https": "http://%(proxy)s/" % {'proxy': proxy.strip("/ ")}
            }
            OutPrintInfo("Proxy", '检测代理可用性中......')
            testurl = "https://www.baidu.com/"
            headers = {"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"}  # 响应头
            try:
                res = requests.get(testurl, timeout=10, proxies=proxies, verify=False, headers=headers)
                if res.status_code == 200:
                    OutPrintInfo("GET", f"www.baidu.com 状态码为:[b bright_green]{str(res.status_code)}")
                    OutPrintInfo("Proxy", "[b bright_green]代理可用")
                    return proxies
            except KeyboardInterrupt:
                OutPrintInfo("Ctrl + C", "手动终止了进程")

                return False
            except:
                OutPrintInfo("Proxy", "[bold bright_red]代理不可用，请更换代理[/bold bright_red]!")
                return False
        else:
            proxies = None
            return proxies

    def __run(self):
        res = {"header": {}, "proxy": None,"bwork":self.__kwargs.get("bwork",False)}
        for key, v in self.__kwargs.items():
            if key == "header":
                res["header"] = {"User-Agent": v}
            if key == "proxy":
                res["proxy"] = self.__proxy(v) if not res["bwork"] else None
        return res["header"],res["proxy"]

    def __iter__(self):
        return iter([self.__headers, self.__proxies])

