#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Fckeditor_Upload_Dir_Scan:
    def get_url(self,input_url,dir):
        try:
            url = input_url + dir
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if req.status_code == 200 and "FCKeditor" in req.text:
                OutPrintInfoSuc("Fckeditor", f'找到目标上传点: {url}')
                if self.batch:
                    OutPutFile("fckeditor_upload_dir.txt",f'找到目标上传点: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("Fckeditor", f'{dir}未找到目标上传点')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Fckeditor",f'{dir}目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Fckeditor", '开始检测Fckeditor上传点...')
        dir = [
            "/FCKeditor/editor/filemanager/browser/default/connectors/test.html",
            "/FCKeditor/editor/filemanager/upload/test.html",
            "/FCKeditor/editor/filemanager/connectors/test.html",
            "/FCKeditor/editor/filemanager/connectors/uploadtest.html",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Type=File&Connector=../../connectors/asp/connector.asp",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/asp/connector.asp",
            "/FCKeditor/_samples/default.html",
            "/FCKeditor/_samples/asp/sample01.asp",
            "/FCKeditor/_samples/asp/sample02.asp",
            "/FCKeditor/_samples/asp/sample03.asp",
            "/FCKeditor/_samples/asp/sample04.asp",
            "/FCKeditor/_samples/default.html",
            "/FCKeditor/editor/fckeditor.htm",
            "/FCKeditor/editor/fckdialog.html",
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/",
            "/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/",
            "/FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/",
            "/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector.jsp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/php/connector.php",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/asp/connector.asp",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/aspx/connector.aspx",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com/fckeditor/editor/filemanager/connectors/jsp/connector.jsp",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp",
            "/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp",
            "/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/aspx/connector.Aspx",
            "/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/php/connector.php",
        ]
        for i in dir:
            self.get_url(url,i)
        if not self.batch:
            OutPrintInfo("Fckeditor", 'Fckeditor上传点检测结束')
