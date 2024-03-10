#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from libs.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from libs.reqset import ReqSet
from libs.output import OutPutFile
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
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Ueditor", '开始检测Fckeditor上传点...')
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
            OutPrintInfo("Ueditor", 'Fckeditor上传点检测结束')
