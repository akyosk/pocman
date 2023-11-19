#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from libs.public.outprint import OutPrintInfo,OutPrintInfoErr
# from tqdm import tqdm
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
class SpringDumnp:
    def dump(self, urllist, proxies):
        try:
            if ('://' not in urllist):
                urllist = str("http://") + str(urllist)
            if str(urllist[-1]) != "/":
                urllist = urllist + "/"
            try:
                requests.packages.urllib3.disable_warnings()
                r = requests.get(urllist, timeout=self.timeout, verify=self.ssl, proxies=proxies)  # 设置超时6秒
                if r.status_code == 503:
                    return
            except KeyboardInterrupt:
                # OutPrintInfo("Spring", "Ctrl + C 手动终止了进程")
                return
            except:
                # OutPrintInfo("Spring", f"URL为{urllist}的目标积极拒绝请求，予以跳过！")
                return
            # OutPrintInfo("Spring", "================开始对目标URL测试SpringBoot敏感文件泄露并下载================")
            # 下载文件，并传入文件名
            url1 = urllist + "actuator/heapdump"
            url2 = urllist + "heapdump"
            url3 = urllist + "heapdump.json"
            url4 = urllist + "gateway/actuator/heapdump"
            url5 = urllist + "hystrix.stream"

            if str(requests.head(url1)) != "<Response [200]>":
                pass
                # OutPrintInfo("Spring", "在 /actuator/heapdump 未发现heapdump敏感文件泄露")
            else:
                url = url1
                OutPrintInfo("Spring",
                             f"发现[b bright_red]/actuator/heapdump[/b bright_red]敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                with open("./result/springDump.txt","a") as w:
                    w.write(f"{url}\n")
                # download(url, "heapdump", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return

            if str(requests.head(url2)) != "<Response [200]>":
                # OutPrintInfo("Spring", "在 /heapdump 未发现heapdump敏感文件泄露")
                pass
            else:
                url = url2
                OutPrintInfo("Spring",
                             f"发现[b bright_red]/heapdump[/b bright_red]敏感文件泄露,下载端点URL为:[b bright_red]{url}[b bright_red]")
                with open("./result/springDump.txt","a") as w:
                    w.write(f"{url}\n")
                # download(url, "heapdump", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            if str(requests.head(url3)) != "<Response [200]>":
                # OutPrintInfo("Spring", "在 /heapdump.json 未发现heapdump敏感文件泄露")
                pass
            else:
                url = url3
                OutPrintInfo("Spring", f"发现/heapdump.json敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                with open("./result/springDump.txt","a") as w:
                    w.write(f"{url}\n")
                # download(url, "heapdump.json", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            if str(requests.head(url4)) != "<Response [200]>":
                # OutPrintInfo("Spring", "在 /gateway/actuator/heapdump 未发现heapdump敏感文件泄露")
                pass
            else:
                url = url4
                OutPrintInfo("Spring",
                             f"发现[b bright_red]/gateway/actuator/heapdump[/b bright_red]敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                with open("./result/springDump.txt","a") as w:
                    w.write(f"{url}\n")
                # download(url, "heapdump", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            if str(requests.head(url5)) != ("<Response [401]>" or "<Response [200]>"):
                # OutPrintInfo("Spring", "在 /hystrix.stream 未发现hystrix监控数据文件泄露，请手动验证")
                pass
            else:
                url = url5
                OutPrintInfo("Spring",
                             f"发现[b bright_red]/hystrix.stream[/b bright_red]监控数据文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
                with open("./result/springDump.txt","a") as w:
                    w.write(f"{url}\n")
                # download(url, "hystrix.stream", proxies)
                # OutPrintInfo("Spring", '文件保存于result文件夹')
                return
            return
        except Exception:
            return
    def main(self,target):
        url = target[0].strip('/ ')
        proxy = target[1]
        self.timeout = int(target[2])
        self.ssl = target[3]
        proxys = {"http":proxy,"https":proxy}
        self.dump(url,proxys)


