# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse
from pub.com.outprint import ATPrintInfoSuc,ATPrintInfoPostSuc
from attack.Attack_Tihuan import attack_tihuan_url_canshu_work
from attack.Attack_Tihuan import post_attack_tihuan_url_canshu_work
from attack.Attack_Tihuan import _header_attack_tihuan_url_canshu_work
from requests.packages.urllib3 import disable_warnings
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor,as_completed,wait
disable_warnings()

class SqlPoc:
    def sql_x_for(self,poc):
        header = {
            "User-Agent": self.__headers,
            "X-Forwarded-For":'id' + poc
        }
        try:
            req = requests.get(self.__base_url,headers=header,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "SQL syntax" in req.text or "PostgreSQL" in req.text or "SQL Server" in req.text or "Oracle error" in req.text or "DB2 SQL error" in req.text or "SQLite" in req.text:
                return True, self.__base_url, "SQL HEADER Inject", req.request.headers
        except Exception:
            pass
    def sqlheader(self,poc):
        header = {
            "User-Agent": self.__headers["User-Agent"] + poc,
        }
        try:
            req = requests.get(self.__base_url,headers=header,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "SQL syntax" in req.text or "PostgreSQL" in req.text or "SQL Server" in req.text or "Oracle error" in req.text or "DB2 SQL error" in req.text or "SQLite" in req.text or "XPATH" in req.text:
                return True, self.__base_url, "SQL HEADER Inject", req.request.headers
        except Exception:
            pass
    def sqlcookie(self,poc):
        header = {
            "User-Agent": self.__headers["User-Agent"],
            "Cookie": f"AGCbcjgsdJKGCUVDSGbcmnaBC{poc}"
        }
        try:
            req = requests.get(self.__base_url,headers=header,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "SQL syntax" in req.text or "PostgreSQL" in req.text or "SQL Server" in req.text or "Oracle error" in req.text or "DB2 SQL error" in req.text or "SQLite" in req.text or "XPATH" in req.text:
                return True, self.__base_url, "SQL Inject", req.request.headers
        except Exception:
            pass
    def sqlcheck(self,url):
        try:
            req = requests.get(url,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "SQL syntax" in req.text or "PostgreSQL" in req.text or "SQL Server" in req.text or "Oracle error" in req.text or "DB2 SQL error" in req.text or "SQLite" in req.text or "XPATH" in req.text:
                return True, url, "SQL Inject", req.request.headers
        except Exception:
            pass
                
    def sqlcheck_post(self,url):
        baseurl = url.split("&attack&")[0]
        data = url.split("&attack&")[-1].strip("&")
        try:
            req = requests.post(baseurl,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout,data=data)
            if "SQL syntax" in req.text or "PostgreSQL" in req.text or "SQL Server" in req.text or "Oracle error" in req.text or "DB2 SQL error" in req.text or "SQLite" in req.text or "XPATH" in req.text:
                return True, url, "SQL POST Inject", req.request.headers,req.request.body
        except Exception:
            pass
    def main(self, target, attack_url_list,progress,__craw_post_url_list):
        self.__attack_url_list = attack_tihuan_url_canshu_work(attack_url_list,"sql")
        if target['proxy']:
            if "://" in target['proxy']:
                self.__proxies = {"https": target['proxy'], "http": target['proxy']}
            else:
                self.__proxies = {"https": "http://" + target['proxy'], "http": "http://" + target['proxy']}
        else:
            self.__proxies = target['proxy']
        self.__base_url = target['url'].strip("/ ")
        self.__headers = {"User-Agent": target['header']}
        self.__ssl = target['ssl']
        self.__threads = int(target['threads'])
        self.__timeout = int(target['timeout'])
        # with Progress(transient=True) as progress:
        tasks = progress.add_task("[b blue]SQL检测...",total=len(self.__attack_url_list))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.sqlcheck,base_url) for base_url in self.__attack_url_list]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks,advance=1)
        wait(futures)

        post_att_url_list = post_attack_tihuan_url_canshu_work(self.__base_url,__craw_post_url_list,"sql")
        if post_att_url_list:
            tasks = progress.add_task("[b blue]SQL POST检测...", total=len(post_att_url_list))
            with ThreadPoolExecutor(self.__threads) as pool:
                futures = [pool.submit(self.sqlcheck_post, base_url) for base_url in post_att_url_list]
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        flag, suc_url, poc_name, req,body = result
                        ATPrintInfoPostSuc(suc_url, poc_name, req,body)
                    progress.update(tasks, advance=1)
            wait(futures)

        header_poc = _header_attack_tihuan_url_canshu_work("sql")
        tasks = progress.add_task("[b blue]SQL HEADER检测...", total=len(header_poc))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.sqlheader, hd_poc) for hd_poc in header_poc]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        tasks = progress.add_task("[b blue]SQL COOKIE检测...", total=len(header_poc))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.sqlcookie, hd_poc) for hd_poc in header_poc]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        tasks = progress.add_task("[b blue]SQL X-For检测...", total=len(header_poc))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.sql_x_for, hd_poc) for hd_poc in header_poc]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)





