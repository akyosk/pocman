# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse
from pub.com.outprint import ATPrintInfoSuc, ATPrintInfoPostSuc
from attack.Attack_Tihuan import attack_tihuan_url_canshu_work
from attack.Attack_Tihuan import post_attack_tihuan_url_canshu_work
from attack.Attack_Tihuan import _header_attack_tihuan_url_canshu_work
from requests.packages.urllib3 import disable_warnings
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor, as_completed, wait

disable_warnings()


class MoBanPoc:
    def mb_check(self, url):
        try:
            req = requests.get(url, headers=self.__headers, proxies=self.__proxies, verify=self.__ssl,
                               timeout=self.__timeout)
            if "603729" in req.text or "603,729" in req.text:
                return True, url, "MB Inject", req.request.headers
        except Exception:
            pass

    def mb_post(self, url):
        baseurl = url.split("&attack&")[0]
        data = url.split("&attack&")[-1].strip("&")
        try:
            req = requests.post(baseurl, headers=self.__headers, proxies=self.__proxies, verify=self.__ssl,
                                timeout=self.__timeout, data=data)
            if "603729" in req.text or "603,729" in req.text:
                return True, url, "MB POST Inject", req.request.headers, req.request.body
        except Exception:
            pass

    def main(self, target, attack_url_list, progress, __craw_post_url_list):
        self.__attack_url_list = attack_tihuan_url_canshu_work(attack_url_list, "mb")
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
        tasks = progress.add_task("[b blue]模版注入检测...", total=len(self.__attack_url_list))
        with ThreadPoolExecutor(self.__threads) as pool:
            futures = [pool.submit(self.mb_check, base_url) for base_url in self.__attack_url_list]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    flag, suc_url, poc_name, req = result
                    ATPrintInfoSuc(suc_url, poc_name, req)
                progress.update(tasks, advance=1)
        wait(futures)

        post_att_url_list = post_attack_tihuan_url_canshu_work(self.__base_url, __craw_post_url_list, "mb")
        if post_att_url_list:
            tasks = progress.add_task("[b blue]模版POST注入检测...", total=len(post_att_url_list))
            with ThreadPoolExecutor(self.__threads) as pool:
                futures = [pool.submit(self.mb_post, base_url) for base_url in post_att_url_list]
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        flag, suc_url, poc_name, req, body = result
                        ATPrintInfoPostSuc(suc_url, poc_name, req, body)
                    progress.update(tasks, advance=1)
            wait(futures)






