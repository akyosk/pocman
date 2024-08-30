# -*-coding:utf-8-*-
import re
import requests
import time
import base64

class Fofacrocs:
    def main(self,target):
        self.logo()
        cookie = input("cookie (回车跳开):").strip(' ')
        print("输入搜索关键字：")
        key = input()
        bkey = base64.b64encode(key.encode()).decode().replace('+', '%2B')
        # print(bkey)
        num = []
        t_list = []
        url = 'https://fofa.info/result?page=' + '&q=' + key + '&qbase64=' + bkey + '&full=true'
        ret = self.pqpqge(url, num, cookie)
        print(ret)
        i = ret[0]
        rem = ret[1]
        jl = []
        if i >= 0 and i < 8:
            numm = 0
            length = int(256 / (2 ** (i + 1)))
            for j in range(0, 256, length):
                if numm < 2 * rem:
                    keys = key + '&&ip="' + str(j) + '.0.0.0/' + str(i + 1) + '"'
                    print("正在爬取中，请稍后。。。")
                    self.pq(keys, cookie)
                else:
                    jl.append(j)
                    break

                numm = numm + 1
            # print(jl)
            length = int(256 / (2 ** i))
            for j in range(jl[0], 256, length):
                keys = key + '&&ip="' + str(j) + '.0.0.0/' + str(i) + '"'
                print("正在爬取中，请稍后。。。")
                self.pq(keys, cookie)
        elif i >= 8 and i < 16:
            length = int(256 / (2 ** (i - 8)))
            for k in range(0, 256):
                for j in range(0, 256, length):
                    keys = key + '&&ip="' + str(k) + '.' + str(j) + '.0.0/' + str(i) + '"'
                    print("正在爬取中，请稍后。。。")
                    self.pq(keys, cookie)
        elif i >= 16 and i < 24:
            length = int(256 / (2 ** (i - 16)))
            for k in range(0, 256):
                for m in range(0, 256):
                    for j in range(0, 256, length):
                        keys = key + '&&ip="' + str(k) + '.' + str(m) + '.' + str(j) + '.0/' + str(i) + '"'
                        print("正在爬取中，请稍后。。。")
                        self.pq(keys, cookie)
        elif i >= 24 and i < 32:
            length = int(256 / (2 ** (i - 24)))
            for k in range(0, 256):
                for m in range(0, 256):
                    for n in range(0, 256):
                        for j in range(0, 256, length):
                            keys = key + '&&ip="' + str(k) + '.' + str(m) + '.' + str(n) + '.' + str(j) + '/' + str(
                                i) + '"'
                            print("正在爬取中，请稍后。。。")
                            self.pq(keys, cookie)

        try:
            input("请输入任意键按回车结束！")
        except:
            pass

    # keys='header="EBRIDGE_JSESSIONID"&&ip="59.0.0.0/9"'
    # pq(keys)
    def pqpqge(self, url, num, cookie):
        # try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept - Encoding': "gzip, deflate",
            'Referer': 'https://fofa.info/',
            'cookie': cookie,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        response = requests.get(url, headers=headers, timeout=20)
        result = response.text
        # print (result)
        page = int(int(re.findall(r"max=\"(.+?)\"", result)[0]))
        print("总共" + str(page) + "页")
        print("请输入您想爬取多少页，建议少一点哦亲！！")
        page = int(input())
        ret = []
        for i in range(0, 30):
            if int(page) >= 2 ** i and int(page) < 2 ** (i + 1):
                ret.append(i)
                ret.append(page - 2 ** i)
                return ret
        # break

    def pq(self, key, cookie):
        # try:
        bkey = base64.b64encode(key.encode()).decode().replace('+', '%2B')
        url = 'https://fofa.info/result?page=' + '&q=' + key + '&qbase64=' + bkey + '&full=true'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Referer': 'https://fofa.info/',
            'Accept - Encoding': "gzip, deflate",
            'cookie': cookie,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        response = requests.get(url, headers=headers, timeout=20)
        result = response.text
        if 'Retry Later' in result:
            print("刷新频率过高,程序等待30s后再次运行,提前结束请按ctrl+c...")
            for x in range(30, -1, -1):
                mystr = "倒计时" + str(x) + "秒"
                print(mystr, end=""),
                print("\b" * (len(mystr) * 2), end="", flush=True)
                time.sleep(1)
        # self.pq(key)
        purllist = re.findall('><span class="hsxa-host"><a href="(.+?)" target="_blank', result)
        f = open("./result/fofaresult.txt", 'a')
        for res in purllist:
            if ('fofa' not in res) and ('baidu' not in res) and ('crl' not in res) and ('crt' not in res) and (
                    '\')' not in res) and ('github' not in res) and ('org' not in res) and ('beian' not in res) and (
                    'baimaohui' not in res) and ('at.alicdn.com' not in res):
                print("\n%s" % res)
                f.write('\n' + res)
        f.close()

    # except requests.exceptions.ConnectTimeout:
    # pass
    def logo(self):
        print("""
	  __         __                                   
	 / _|       / _|                                  
	| |_  ___  | |_  __ _   ___  _ __  ___   ___  ___ 
	|  _|/ _ \ |  _|/ _` | / __|| '__|/ _ \ / __|/ __|
	| | | (_) || | | (_| || (__ | |  | (_) |\\__ \\\\__ \\
	|_|  \___/ |_|  \__,_| \___||_|   \___/ |___/|___/ 

										   --by:DSB v2.0           
	""")

