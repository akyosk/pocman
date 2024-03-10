#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()


class JieLinkWsqScan:
    def run(self, urls):
        url = urls + '/Report/ParkCommon/GetDicDetailList?type=enmPayType'
        try:
            response = requests.post(url, headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)
            if response.status_code == 200 and response.url == url:
                OutPrintInfoSuc("JieLink", f'存在JieLink未授权 {url}')
                if self.batch:
                    OutPutFile("jielink_wsq.txt",url)

            else:
                if not self.batch:
                    OutPrintInfo("JieLink", '不存在JieLink未授权')
        except Exception:
            if not self.batch:
                OutPrintInfo("JieLink","目标访问出错")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("JieLink", '开始执行JieLink未授权...')
        self.run(url)

        if not self.batch:
            OutPrintInfo("JieLink",'JieLink未授权检测结束')