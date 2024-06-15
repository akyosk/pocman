#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("JieLink", '开始执行JieLink未授权...')
        self.run(url)

        if not self.batch:
            OutPrintInfo("JieLink",'JieLink未授权检测结束')