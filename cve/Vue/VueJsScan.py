#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import concurrent.futures
import requests
import urllib3
import re
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from concurrent.futures import ThreadPoolExecutor,wait
from bs4 import BeautifulSoup
from rich.progress import Progress
from rich.prompt import Prompt
from urllib.parse import urlparse
urllib3.disable_warnings()
class VueJsScaner:
    def get_run(self,url):
        try:
            response = requests.get(url,headers=self.head,proxies=self.proxies,verify=self.verify)
            response.encoding = response.apparent_encoding
            soup = BeautifulSoup(response.text,"html.parser")
            titles = soup.find("title")
            if titles:
                title = titles.text
            else:
                title = "未找到Title"
            res = f"[[b green]Get[/b green]] Url:[b bright_red]{url}[/b bright_red] Title:[b bright_red]{title}[/b bright_red] 长度:[b bright_red]{str(len(response.text))}[/b bright_red] 响应:[b bright_red]{response.status_code}[/b bright_red]"
            return res
        except Exception as e:
            pass

    def post_run(self, url):
        data = 'page=1&id=1'
        try:
            response = requests.post(url,data=data,headers=self.head,proxies=self.proxies,verify=self.verify)
            response.encoding = response.apparent_encoding
            soup = BeautifulSoup(response.text, "html.parser")
            titles = soup.find("title")
            if titles:
                title = titles.text
            else:
                title = "未找到Title"
            res = f"[[b green]Post[/b green]] Url:[b bright_red]{url}[/b bright_red] Title:[b bright_red]{title}[/b bright_red] 长度:[b bright_red]{str(len(response.text))}[/b bright_red] 响应:[b bright_red]{response.status_code}[/b bright_red]"
            return res
        except Exception as e:
            pass

    def pathscan(self,domain,res_list,thread):
        api_list = []
        num = 1
        OutPrintInfo("VUE", '开始解析接口文件')
        for j in res_list:
            url2 = domain + "/" + j
            response2 = requests.get(url2, headers=self.head, proxies=self.proxies, verify=self.verify)
            response2.encoding = response2.apparent_encoding
            if response2.status_code == 200:
                OutPrintInfo("VUE", f'开始解析第{num}个接口文件')
                OutPrintInfo("VUE", f'接口文件: {url2}')
                num += 1
                # res2 = re.findall('path:"(.*?)"',response2.text)
                res2 = re.findall(r'path:\s*"/(.*?)"', response2.text)
                for p in res2:
                    api = p.lstrip('/')
                    if api not in api_list:
                        api_list.append(domain + '/#/' + api)
                if not api_list:
                    OutPrintInfo("VUE", '接口文件未能找到路径')
                    return

        OutPrintInfo("VUE", '接口文件解析结束')
        OutPrintInfo("VUE", f'共获取到{str(len(api_list))}个路径')
        OutPrintInfo("VUE", '开始测试接口')
        res_out = []
        if api_list:
            get_ch = Prompt.ask("是否尝试Get检测[b bright_red](y/n)[/b bright_red]")
            if get_ch == 'y':
                with Progress(transient=True) as progress:
                    tasks = progress.add_task("[b green]GET验证...", total=len(api_list))
                    with ThreadPoolExecutor(int(thread)) as pool:
                        futures = [pool.submit(self.get_run, api_url) for api_url in api_list]
                        for future in concurrent.futures.as_completed(futures):
                            res_out.append(future.result())
                            progress.update(tasks,advance=1)
                    wait(futures)


            post_ch = Prompt.ask("是否尝试Post检测[b bright_red](y/n)[/b bright_red]")
            if post_ch == 'y':
                with Progress(transient=True) as progress:
                    tasks = progress.add_task("[b cyan]POST验证...",total=len(api_list))
                    with ThreadPoolExecutor(int(thread)) as pool:
                        futures = [pool.submit(self.post_run, api_url) for api_url in api_list]
                        for future in concurrent.futures.as_completed(futures):
                            res_out.append(future.result())
                            progress.update(tasks,advance=1)
                    wait(futures)

            for jg in res_out:
                OutPrintInfo("VUE", jg)
    def main(self,target):
        res_list = []
        url = target["url"].strip('/ ')
        thread = int(target["threads"])
        proxy = target["proxy"]
        self.verify = target["ssl"]
        cookie = target["cookie"]
        self.head = {"User-Agent": target['header'],'Cookie': cookie}
        _, self.proxies = ReqSet(proxy=proxy)
        chk_domain = urlparse(url)
        https = chk_domain.scheme
        domain = https + '://' + chk_domain.netloc

            
        response = requests.get(url,headers=self.head,proxies=self.proxies,verify=self.verify)
        response.encoding = response.apparent_encoding
        # print(response.text)
        if '/app.' in response.text:
            OutPrintInfo("VUE", '发现接口文件')
        else:
            OutPrintInfo("VUE", '未发现接口文件')
            return

        OutPrintInfo("VUE", '开始尝试第一种方式获取接口文件信息')
        res = re.findall(r'src=["\']([^"\']*app\.[^"\']+)["\']',response.text)
        OutPrintInfo("VUE", '进行接口文件获取')

        for i in res:
            if '<' not in i and '>' not in i:
                OutPrintInfo("VUE", f'找到文件: [b bright_red]{i}[/b bright_red]')
                res_list.append(i)

        OutPrintInfo("VUE", '接口文件获取结束')
        if res_list:
            self.pathscan(domain,res_list,thread)
        else:
            OutPrintInfo("VUE", f'{"~"*50}')
            OutPrintInfo("VUE", '开始尝试第二种方式获取接口文件信息')
            res = re.findall(r'src=([^>]+app\.[a-zA-Z0-9]+\.js)', response.text)
            for i in res:
                if '<' not in i and '>' not in i:
                    OutPrintInfo("VUE", f'找到文件: [b bright_red]{i}[/b bright_red]')
                    res_list.append(i)

            if res_list:
                self.pathscan(domain, res_list, thread)
            else:
                OutPrintInfo("VUE", '未能获取接口路径')
            return