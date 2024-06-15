#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
class SpringDumpScan:
    def dump(self, urllist):
        try:
            if ('://' not in urllist):
                urllist = str("http://") + str(urllist)
            if str(urllist[-1]) != "/":
                urllist = urllist + "/"
            try:
                requests.packages.urllib3.disable_warnings()
                r = requests.get(urllist, timeout=self.timeout, verify=self.ssl, proxies=self.proxy,headers=self.headers)  # 设置超时6秒
                if r.status_code == 503:
                    return
            except Exception:
                if not self.batch:
                    OutPrintInfo("Spring", "目标访问出错")
                return
            # OutPrintInfo("Spring", "================开始对目标URL测试SpringBoot敏感文件泄露并下载================")
            # 下载文件，并传入文件名
            url1 = urllist + "actuator/heapdump"
            url2 = urllist + "heapdump"
            url3 = urllist + "heapdump.json"
            url4 = urllist + "gateway/actuator/heapdump"
            url5 = urllist + "hystrix.stream"

            if str(requests.head(url1)) != "<Response [200]>":
                if not self.batch:
                    OutPrintInfo("Spring", "在 /actuator/heapdump 未发现heapdump敏感文件泄露")
            else:
                url = url1
                OutPrintInfoSuc("Spring",
                             f"发现/actuator/heapdump敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                if self.batch:
                    with open("./result/spring_dump.txt","a") as w:
                        w.write(f"{url}\n")
                return

            if str(requests.head(url2)) != "<Response [200]>":
                if not self.batch:
                    OutPrintInfo("Spring", "在 /heapdump 未发现heapdump敏感文件泄露")

            else:
                url = url2
                OutPrintInfoSuc("Spring",
                             f"发现/heapdump敏感文件泄露,下载端点URL为:[b bright_red]{url}[b bright_red]")
                if self.batch:
                    with open("./result/spring_dump.txt","a") as w:
                        w.write(f"{url}\n")
                # download(url, "heapdump", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            if str(requests.head(url3)) != "<Response [200]>":
                if not self.batch:
                    OutPrintInfo("Spring", "在 /heapdump.json 未发现heapdump敏感文件泄露")

            else:
                url = url3
                OutPrintInfoSuc("Spring", f"发现/heapdump.json敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                if self.batch:
                    with open("./result/spring_dump.txt","a") as w:
                        w.write(f"{url}\n")
                # download(url, "heapdump.json", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            if str(requests.head(url4)) != "<Response [200]>":
                if not self.batch:
                    OutPrintInfo("Spring", "在 /gateway/actuator/heapdump 未发现heapdump敏感文件泄露")

            else:
                url = url4
                OutPrintInfoSuc("Spring",
                             f"发现/gateway/actuator/heapdump敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                if self.batch:
                    with open("./result/spring_dump.txt","a") as w:
                        w.write(f"{url}\n")
                # download(url, "heapdump", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            if str(requests.head(url5)) != ("<Response [401]>" or "<Response [200]>"):
                if not self.batch:
                    OutPrintInfo("Spring", "在 /hystrix.stream 未发现hystrix监控数据文件泄露，请手动验证")

            else:
                url = url5
                OutPrintInfoSuc("Spring",
                             f"发现/hystrix.stream监控数据文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                if self.batch:
                    with open("./result/spring_dump.txt","a") as w:
                        w.write(f"{url}\n")
                # download(url, "hystrix.stream", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            return
        except Exception:
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.timeout = int(target["timeout"])
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        self.dump(url)


