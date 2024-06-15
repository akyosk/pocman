#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Ueditor_Upload_Dir_Scan:
    def get_url(self,input_url,dir):
        try:
            url = input_url + dir
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200 and "Ueditor" in req.text:
                OutPrintInfoSuc("Ueditor", f'找到目标上传点: {url}')
                if self.batch:
                    OutPutFile("ueditor_upload_dir.txt",f'找到目标上传点: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Ueditor", f'{dir}未找到目标上传点')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Ueditor",f'{dir}目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Ueditor", '开始检测Ueditor上传点...')
        dir = [
            "/ueditor/index.html",
            "/ueditor/asp/controller.asp?action=uploadimage",
            "/ueditor/asp/controller.asp?action=uploadfile",
            "/ueditor/net/controller.ashx?action=uploadimage",
            "/ueditor/net/controller.ashx?action=uploadfile",
            "/ueditor/php/controller.php?action=uploadfile",
            "/ueditor/php/controller.php?action=uploadimage",
            "/ueditor/jsp/controller.jsp?action=uploadfile",
            "/ueditor/jsp/controller.jsp?action=uploadimage",
            "/ueditor/net/controller.ashx?action=listfile",
            "/ueditor/net/controller.ashx?action=listimage",
        ]
        for i in dir:
            self.get_url(url,i)
        if not self.batch:
            OutPrintInfo("Ueditor", 'Ueditor上传点检测结束')
