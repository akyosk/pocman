#!/user/bin/env python3
# -*- coding: utf-8 -*-
import time

import requests, re
from requests.packages import urllib3
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from pub.com.outprint import OutPrintInfo, OutPrintInfoErr,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from attack.Other_Poc_Attack import Other_Poc_Attack_Run
from rich.progress import Progress
from rich.prompt import Prompt
urllib3.disable_warnings()
class AT_RUN_WORK:
    def __init__(self):
        self.__refer_url = None
        self.__craw_baseurl_list = []
        self.__base_attack_url = []
        self.__base_url = None
        self.__craw_num = 1
        self.__craw_domian = []
        self.__craw_max_num = None
        self.__craw_post_url_list = []

    def _post_craw(self,html_code):
        try:
            soup = BeautifulSoup(html_code, 'html.parser')

            post_requests = soup.find_all('form', method='post')
            post_data_list = []
            post_data = {}
            post_data['parmes'] = []
            # 打印POST请求的相关信息
            for post_request in post_requests:
                action_url = post_request.get('action')
                post_data['path'] = action_url
                # 获取表单中的所有输入字段
                input_fields = post_request.find_all('input')
                # 构建POST请求的参数字典
                if input_fields:
                    for input_field in input_fields:
                        field_name = input_field.get('name')
                        if field_name:
                            post_data['parmes'].append(field_name)
                        else:
                            post_data['parmes'].append("uuid")
                    post_data_list.append(post_data)
            if "path" in post_data:
                return post_data_list
            else:
                return None
        except Exception:
            pass
    def crawer(self,url,html_code=None):
        try:
            if not html_code:
                html_code = requests.get(url, headers=self.headers, timeout=self.timeout, verify=self._ssl, proxies=self.proxy).text
            list_r = []
            # print(html_code)
            page_pattern = re.compile(r'["\'](?:page|path)["\']\s*:\s*"\s*(\S+?)\s*"')
            href_pattern = re.compile(r'(?i)href(?:"|\'|["\']|["\']\s*:\s*["\']|[\s=:]\s*["\'])(https?://\S+?|/\S+?|.*?)["\']')
            src_pattern = re.compile(r'(?i)src(?:"|\'|["\']|["\']\s*:\s*["\']|[\s=:]\s*["\'])(https?://\S+?|/\S+?|.*?)["\']')
            link_pattern = re.compile(r'(?i)link(?:"|\'|["\']|["\']\s*:\s*["\']|[\s=:]\s*["\'])(https?://\S+?|/\S+?|.*?)["\']')
            url_pattern = re.compile(r'(?i)url(?:"|\'|["\']|["\']\s*:\s*["\']|[\s=:]\s*["\'])(https?://\S+?|/\S+?|.*?)["\']')
            srcset_pattern = re.compile(r'(?i)srcset(?:"|\'|["\']|["\']\s*:\s*["\']|[\s=:]\s*["\'])(https?://\S+?|/\S+?|.*?)["\']')
            all_links = set(url_pattern.findall(html_code) + src_pattern.findall(html_code) + page_pattern.findall(
                html_code) + href_pattern.findall(html_code) + link_pattern.findall(html_code) + srcset_pattern.findall(html_code))

            for link in all_links:
                if "(" in link or "{" in link or "," in link:
                    continue
                if ";" in link:
                    link = link.split(";")[0]
                if "://" not in link:
                    link = url.split('/')[0] + "//" + url.split('/')[2] + "/" + link.strip("*").strip("@").strip("{}").strip("()").strip("/ ")
                    if link not in list_r and link not in self.__craw_baseurl_list:
                        if self.ck_url_domain(link):
                            list_r.append(link)
                            self.__craw_baseurl_list.append(link)
                elif link[:1] == "//":
                    link = url.split("://")[0] + ":" + link.strip("*").strip("@").strip("{}").strip("()").strip("/ ")
                    if link not in list_r and link not in self.__craw_baseurl_list:
                        if self.ck_url_domain(link):
                            list_r.append(link)
                            self.__craw_baseurl_list.append(link)
                else:
                    if link not in list_r and link not in self.__craw_baseurl_list:
                        if self.ck_url_domain(link):
                            list_r.append(link)
                            self.__craw_baseurl_list.append(link)

            post_list = self._post_craw(html_code)
            if post_list:
                for post_url in post_list:
                    if post_url not in self.__craw_post_url_list:
                        self.__craw_post_url_list.append(post_url)

            if list_r:
                for link in list_r:
                    with open(f"./result/{self.__file_name}", "a") as w:
                        w.write(link + "\n")
                return list_r

        except Exception:
            pass

    def ck(self,url):
        try:
            req = requests.get(url,headers=self.headers, timeout=self.timeout, verify=self._ssl, proxies=self.proxy)
            if req.status_code == 403:
                choose = Prompt.ask("[b blue]检测到目标响应403是否继续检测",choices=["y","n"])
                if choose == 'n':
                    return None
            elif req.url.split('/')[2] != url.split('/')[2]:
                choose = Prompt.ask(f"[b yellow]检测到目标跳转网址:{req.url},是否加入跳转网址进行检测",choices=["y","n"])
                if choose == 'y':
                    self.__refer_url = req.url


            return req.text if req.text else None
        except Exception:
            OutPrintInfo("ATTACK","[b yellow]目标请求无法访问")

    def ck_url_domain(self,url):

        def has_letters(input_str):
            return any(char.isalpha() for char in input_str)

        url_domain = url.split("/")[2]
        if has_letters(url_domain):
            domain = '.'.join(url_domain.split('.')[1:])
            if self.__refer_url:
                if domain in self.__base_url.split("/")[2] or domain in self.__refer_url.split("/")[2]:
                    return True
            else:
                if domain in self.__base_url.split("/")[2]:
                    if domain not in self.__craw_domian:
                        self.__craw_domian.append(domain)
                    return True
        else:
            if url_domain == self.__base_url.split('/')[2] or url_domain == self.__refer_url.split('/')[2]:
                if url_domain not in self.__craw_domian:
                    self.__craw_domian.append(url_domain)
                return True
        return False
    def ck_url_canshu(self):
        for url in self.__craw_baseurl_list:
            if "=" in url:
                # print(url)
                self.__base_attack_url.append(url)
            if "admin" in url:
                OutPrintInfoSuc("ATTACK",f"找到敏感路径: {url}")
    def pools(self,craw_list_url):
        req_list = []
        with Progress(transient=True) as progress:
            tasks = progress.add_task(f"[b green]网页第 [b red]{str(self.__craw_num)}[/b red] 批数据采集...", total=len(craw_list_url))
            with ThreadPoolExecutor(self._threads) as pool:
                futures = [pool.submit(self.crawer,baseurl,None) for baseurl in craw_list_url]
                for future in as_completed(futures):
                    res_list = future.result()
                    if self.__craw_max_num:
                        if len(self.__craw_baseurl_list) >= int(self.__craw_max_num):
                            OutPrintInfo("ATTACK", f"[b cyan]目标爬取到达设置最大值: [b red]{self.__craw_max_num} 需等待所有线程结束")
                            pool.shutdown(wait=False)
                            # for f in as_completed(futures):
                            #     if not f.done():
                            #         f.cancel()
                            return
                        time.sleep(1)
                    if res_list:
                        for i in res_list:
                            req_list.append(i)
                    progress.update(tasks, advance=1)
            wait(futures)
        self.__craw_num += 1
        if req_list:
            self.pools(req_list)

    def main(self,target):
        url = target["url"].strip('/ ')
        self.__base_url = url
        self.cookie = target["cookie"]
        header = target["header"]
        self.timeout = int(target['timeout'])
        self._threads = int(target["threads"])
        proxy = target["proxy"]
        self._ssl = target["ssl"]
        self.__craw_max_num = target["max"]
        self.__file_name = "attack_"+urlparse(url).netloc.replace(".","_")+".txt"
        self.headers, self.proxy = ReqSet(header=header,proxy=proxy)
        req_text = self.ck(url)
        if req_text:
            craw_list_url = self.crawer(url,req_text)
        else:
            return OutPrintInfo("ATTACK",f"[b yellow]目标 {url} 访问未获取到任何信息")
        if craw_list_url:
            self.pools(craw_list_url)
        else:
            return OutPrintInfo("ATTACK",f"[b yellow]目标 {url} 未获取到任何利用信息")

        if self.__craw_baseurl_list:
            self.ck_url_canshu()
            if not self.__base_attack_url:
                id_poc_list = [
                    "/?id=1",
                    "/?uid=1",
                    "/?q=1",
                    "/?s=1",
                    "/?userid=1",
                    "/?query=1",
                    "/?search=1",
                    "/?group=1",
                    "/?name=1",
                    "/?t=1",
                    "/?u=1",
                    "/?w=1",
                    "/?x=1",
                    "/?y=1",
                    "/?file=1",
                    "/?f=1",
                    "/?filename=1",
                    "/?username=1",
                    "/?code=1",
                    "/?pid=1",
                    "/?sid=1",
                    "/?url=1",

                ]
                for ids in id_poc_list:
                    self.__base_attack_url.append(url+ids)
        Other_Poc_Attack_Run().main(target, self.__base_attack_url, self.__craw_post_url_list)
        OutPrintInfo("ATTACK",f"目标 {url} 检测结束")


        if self.__craw_domian:
            with open(f"./result/{self.__file_name}","a") as w:
                w.write("\n域名信息:\n")
                for i in self.__craw_domian:
                    w.write(i+"\n")
        OutPrintInfo("ATTACK",f"扫描信息保存于result/{self.__file_name}")



