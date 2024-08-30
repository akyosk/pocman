#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Kindeditor_Upload_Dir_Scan:
    def get_url(self,input_url,dir):
        try:
            url = input_url + dir
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "请选择文件" in req.text:
                OutPrintInfoSuc("Kindeditor", f'找到目标上传点: {url}')
                if self.batch:
                    OutPutFile("kindeditor_upload_dir.txt",f'找到目标上传点: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Kindeditor", f'{dir}未找到目标上传点')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Kindeditor",f'{dir}目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Kindeditor", '开始检测Kindeditor上传点...')
        dir = [
            "/Scripts/kindEditor/asp.net/upload_json.ashx?dir=file",
            "/kindeditor/asp/upload_json.asp?dir=file",
            "/kindeditor/asp.net/upload_json.ashx?dir=file",
            "/kindeditor/jsp/upload_json.jsp?dir=file",
            "/kindeditor/php/upload_json.php?dir=file",
            "/asp/upload_json.asp",
            "/asp.net/upload_json.ashx",
            "/jsp/upload_json.jsp",
            "/php/upload_json.php",

        ]
        for i in dir:
            self.get_url(url,i)
        if not self.batch:
            OutPrintInfo("Kindeditor", 'Kindeditor上传点检测结束')
