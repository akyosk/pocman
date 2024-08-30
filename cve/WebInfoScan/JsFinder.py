#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time
import requests, re
import urllib3
from requests.packages import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from rich.progress import Progress
class JsFinderScan:
    def __init__(self):
        self._ssl = None
        self._proxy = None
        self.cookie = None
        self._threads = None
    def extract_URL(self,JS):
        pattern_raw = r"""
    	  (?:"|')                               # Start newline delimiter
    	  (
    	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    	    |
    	    ((?:/|\.\./|\./)                    # Start with /,../,./
    	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
    	    |
    	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
    	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    	    |
    	    ([a-zA-Z0-9_\-]{1,}                 # filename
    	    \.(?:php|asp|aspx|jsp|json|
    	         action|html|js|txt|xml)             # . + extension
    	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
    	  )
    	  (?:"|')                               # End newline delimiter
    	"""
        pattern = re.compile(pattern_raw, re.VERBOSE)
        result = re.finditer(pattern, str(JS))
        if result == None:
            return None
        js_url = []
        return [match.group().strip('"').strip("'") for match in result
                if match.group() not in js_url]

    # Get the page source
    def Extract_html(self,URL):
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
                  "Cookie": self.cookie}
        try:
            raw = requests.get(URL, headers=header, timeout=3, verify=self._ssl,proxies=self._proxy)
            raw = raw.content.decode("utf-8", "ignore")
            # print(1)
            return raw
        except:
            return None

    # Handling relative URLs
    def process_url(self,URL, re_URL):
        black_url = ["javascript:"]  # Add some keyword for filter url.
        URL_raw = urlparse(URL)
        ab_URL = URL_raw.netloc
        host_URL = URL_raw.scheme
        if re_URL[0:2] == "//":
            result = host_URL + ":" + re_URL
        elif re_URL[0:4] == "http":
            result = re_URL
        elif re_URL[0:2] != "//" and re_URL not in black_url:
            if re_URL[0:1] == "/":
                result = host_URL + "://" + ab_URL + re_URL
            else:
                if re_URL[0:1] == ".":
                    if re_URL[0:2] == "..":
                        result = host_URL + "://" + ab_URL + re_URL[2:]
                    else:
                        result = host_URL + "://" + ab_URL + re_URL[1:]
                else:
                    result = host_URL + "://" + ab_URL + "/" + re_URL
        else:
            result = URL
        return result

    def find_last(self,string, str):
        positions = []
        last_position = -1
        while True:
            position = string.find(str, last_position + 1)
            if position == -1: break
            last_position = position
            positions.append(position)
        return positions

    def find_by_url(self,url, js=False):
        if js == False:
            try:
                OutPrintInfo("JsFinder",f"{url}")
            except:
                OutPrintInfoErr("请提交正确的URL如https://www.baidu.com")
            html_raw = self.Extract_html(url)
            if html_raw == None:
                OutPrintInfo("JsFinder",f"无法访问{url}")
                return None
            # print(html_raw)
            html = BeautifulSoup(html_raw, "html.parser")
            html_scripts = html.findAll("script")
            script_array = {}
            script_temp = ""
            for html_script in html_scripts:
                script_src = html_script.get("src")
                if script_src == None:
                    script_temp += html_script.get_text() + "\n"
                else:
                    purl = self.process_url(url, script_src)
                    script_array[purl] = self.Extract_html(purl)
            script_array[url] = script_temp
            allurls = []
            for script in script_array:
                # print(script)
                temp_urls = self.extract_URL(script_array[script])
                if len(temp_urls) == 0: continue
                for temp_url in temp_urls:
                    allurls.append(self.process_url(script, temp_url))
            result = []
            for singerurl in allurls:
                url_raw = urlparse(url)
                domain = url_raw.netloc
                positions = self.find_last(domain, ".")
                miandomain = domain
                if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
                # print(miandomain)
                suburl = urlparse(singerurl)
                subdomain = suburl.netloc
                # print(singerurl)
                if miandomain in subdomain or subdomain.strip() == "":
                    if singerurl.strip() not in result:
                        result.append(singerurl)
            return result
        return sorted(set(self.extract_URL(self.Extract_html(url)))) or None

    def find_subdomain(self,urls, mainurl):
        url_raw = urlparse(mainurl)
        domain = url_raw.netloc
        miandomain = domain
        positions = self.find_last(domain, ".")
        if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
        subdomains = []
        for url in urls:
            suburl = urlparse(url)
            subdomain = suburl.netloc
            # print(subdomain)
            if subdomain.strip() == "": continue
            if miandomain in subdomain:
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
        return subdomains

    def find_by_url_deep(self,url):
        html_raw = self.Extract_html(url)
        # print(html_raw)
        if html_raw == None:
            OutPrintInfo("JsFinder",f"无法访问{url}")
            return None
        html = BeautifulSoup(html_raw, "html.parser")
        html_as = html.findAll("a")
        links = []
        for html_a in html_as:
            src = html_a.get("href")
            if src == "" or src == None: continue
            link = self.process_url(url, src)
            if link not in links:
                links.append(link)
        if links == []: return None
        OutPrintInfo("JsFinder",f"共找到[b bright_red]{str(len(links))}[/b bright_red]个链接")
        urls = []
        i = len(links)
        for link in links:
            temp_urls = self.find_by_url(link)
            if temp_urls == None: continue
            OutPrintInfo("JsFinder",f"从{str(i)}个结果中找到[b bright_red]{str(len(temp_urls))}[/b bright_red]个URL在{link}")
            for temp_url in temp_urls:
                if temp_url not in urls:
                    urls.append(temp_url)
            i -= 1
        return urls

    def giveresult(self,urls, domian):
        if urls == None:
            return None
        OutPrintInfo("JsFinder",f"共找到[b bright_red]{str(len(urls))}[/b bright_red]个URL:")
        content_url = ""
        content_subdomain = ""
        for url in urls:
            content_url += url + "\n"
            OutPrintInfo("JsFinder",f"{url}")
        subdomains = self.find_subdomain(urls, domian)
        OutPrintInfo("JsFinder-Subdomain", f"共找到[b bright_red]{str(len(subdomains))}[/b bright_red]个域名:")
        for subdomain in subdomains:
            content_subdomain += subdomain + "\n"
            OutPrintInfo("JsFinder-Subdomain",f"{subdomain}")
        if urls:
            choose = Prompt.ask("[b blue]是否对结果进行二次验证[/b blue][b red](y/n)[b red]")
            # choose = input('>>> 是否对结果进行二次验证(y/n): ')
            if choose == 'y':
                self.check(urls)
            else:
                pass

    def run(self,url):
        header = {
            "User-Agent": self.headers["User-Agent"]
        }
        try:
            urllib3.disable_warnings()
            response = requests.get(url, headers=header, verify=self._ssl,proxies=self._proxy)
            res_str = f"[b green]GET[/b green] URL:{url} 长度:[b bright_red]{str(len(response.text))}[/b bright_red] 响应:[b bright_red]{str(response.status_code)}[/b bright_red]"

            return res_str
        except Exception as e:
            pass

    def run2(self,url):
        header = {
            "User-Agent": self.headers["User-Agent"]
        }
        try:
            urllib3.disable_warnings()
            data = 'page=1&id=1'
            response = requests.post(url, headers=header, data=data, verify=self._ssl,proxies=self._proxy)
            res_str = f"[b blue]POST[/b blue] URL:{url} 长度:[b bright_red]{str(len(response.text))}[/b bright_red] 响应:[b bright_red]{str(response.status_code)}[/b bright_red]"

            return res_str
        except Exception as e:
            pass

    def check(self,urls):
        res = []
        with Progress(transient=True) as progress:
            tasks = progress.add_task("[cyan] GET请求中...",total=len(urls),)
            with ThreadPoolExecutor(self._threads) as pool:
                futures = [pool.submit(self.run, url.strip()) for url in urls]
                for future in as_completed(futures):
                    if future.result():
                        res.append(future.result())
                    progress.update(tasks,advance=1)

            wait(futures)
        time.sleep(1)
        post_ch = Prompt.ask("[b blue]是否尝试Post检测[/b blue][b red](y/n)[b red]")
        if post_ch == 'y':
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[green] POST请求中...",total=len(urls))
                with ThreadPoolExecutor(self._threads) as pool:
                    futures = [pool.submit(self.run2, url.strip()) for url in urls]
                    for future in as_completed(futures):
                        if future.result():
                            res.append(future.result())
                        progress.update(tasks,advance=1)
                wait(futures)
        time.sleep(0.5)
        for i in res:
            OutPrintInfo("JsFinder", i)




    def main(self,target):
        urllib3.disable_warnings()
        url = target["url"].strip('/ ')
        self.cookie = target["cookie"]
        depth = target["depth"]
        self._threads = int(target["threads"])
        proxy = target["proxy"]
        self._ssl = target["ssl"]
        header = target["header"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        if depth is not True:
            urls = self.find_by_url(url)
            self.giveresult(urls, url)
        else:
            urls = self.find_by_url_deep(url)
            self.giveresult(urls, url)
