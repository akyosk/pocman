#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import re
import urllib3
from termcolor import colored
from colorama import Fore
from pub.com.reqset import ReqSet
urllib3.disable_warnings()



#
class WpRestScan:
    def fetchdata(self):
        global mediaflag, postsflag, usersflag, mediaID, postID, userID
        print(Fore.GREEN + "[+] Fetching endpoints from WP-JSON...")
        r = requests.get(url,headers=self.header,verify=self.ssl,proxies=self.proxy)
        if r.status_code != 200:
            print(Fore.YELLOW + "WP-JSON does not seem to be accessible :( \nExiting...")
            return False
        print(Fore.GREEN + "[+] REST Endpoints successfully fetched.")
        if usersflag or (not postsflag and not mediaflag and not usersflag):
            try:
                print(Fore.GREEN + "[+] Fetching a valid user ID...")
                usersR = requests.get(url + '/wp/v2/users', headers=self.header,verify=self.ssl,proxies=self.proxy)
                userID = int(usersR.text[usersR.text.index(':') + 1:usersR.text.index(',')])
                print(Fore.GREEN + "[+] Valid user ID -> " + Fore.RED+ str(userID))
            except:
                print(Fore.YELLOW + "Unable to fetch user ID.")

        if mediaflag or (not postsflag and not mediaflag and not usersflag):
            try:
                print(Fore.GREEN + "[+] Fetching a valid media ID...")
                mediaR = requests.get(url + '/wp/v2/media', headers=self.header,verify=self.ssl,proxies=self.proxy)
                mediaID = int(mediaR.text[mediaR.text.index(':') + 1:mediaR.text.index(',')])
                print(Fore.GREEN + "[+] Valid media ID -> " + Fore.RED + str(mediaID))
            except:
                print(Fore.YELLOW + "Unable to fetch media ID.")
        if postsflag or (not postsflag and not mediaflag and not usersflag):
            try:
                print(Fore.GREEN + "[+] Fetching a valid post ID...")
                postsR = requests.get(url + '/wp/v2/posts', headers=self.header,verify=self.ssl,proxies=self.proxy)
                postID = int(postsR.text[postsR.text.index(':') + 1:postsR.text.index(',')])
                print(Fore.GREEN + "[+] Valid post ID -> " + Fore.RED + str(postID))

            except:
                print(Fore.YELLOW + "Unable to fetch post ID.")
        print(Fore.GREEN + '[+] Initiating scan...')
        return r

    def output(self,method, url, status):
        global users, media, posts
        if '/users' in url and users == 1:
            print(colored("USERS ENDPOINTS", 'blue'))
            users = 0
        if '/media' in url and media == 1:
            print(colored("MEDIA ENDPOINTS", 'blue'))
            media = 0
        if '/posts' in url and posts == 1:
            print(colored("POSTS ENDPOINTS", 'blue'))
            posts = 0
        if status == 200:
            print(Fore.GREEN + str(method) + "\t" + str(url) + "\t" + Fore.GREEN + str(status))
        elif status == 400:
            print(Fore.YELLOW +str(method) + "\t" + str(url) + "\t" + Fore.YELLOW + str(status))
        elif status == 401:
            print(Fore.RED + str(method) + "\t" + str(url) + "\t" + Fore.RED + str(status))
        elif status == 500:
            print(Fore.BLUE + str(method) + "\t" + str(url) + "\t" + Fore.BLUE + str(status))
        else:
            print(Fore.WHITE + str(method) + "\t" + str(url) + "\t" + Fore.WHITE + str(status))



    def run(self):
        global mediaflag, postsflag, usersflag
        r = self.fetchdata()
        if not r:
            print(Fore.RED + "未找到检测对象相关接口...")
            return
        jsondata = r.json()
        routes = jsondata['routes']
        for route in routes:
            if mediaflag and not usersflag and not postsflag:
                if not '/media' in route:
                    continue
            if usersflag and not mediaflag and not postsflag:
                if not '/users' in route:
                    continue
            if postsflag and not mediaflag and not usersflag:
                if not '/posts' in route:
                    continue
            if postsflag and mediaflag and usersflag:
                if not '/posts' in route or not '/media' in route or not '/posts' in route:
                    continue
            if postsflag and mediaflag and not usersflag:
                if not '/posts' in route and not '/media' in route:
                    continue
            if postsflag and usersflag and not mediaflag:
                if not '/posts' in route and not '/users' in route:
                    continue
            if usersflag and mediaflag and not postsflag:
                if not '/users' in route and not '/media' in route:
                    continue
            for endpoint in routes[route]['endpoints']:
                for method in endpoint['methods']:
                    if '?P' in route:
                        if '/media' in route and mediaID:
                            route = re.sub("\(\?P.+\)", str(mediaID), route)
                        elif '/posts' in route and postID:
                            route = re.sub("\(\?P.+\)", str(postID), route)
                        elif '/users' in route and userID:
                            route = re.sub("\(\?P.+\)", str(userID), route)
                        else:
                            route = re.sub("\(\?P.+\)", "1", route)
                    finalurl = url + route + '?'
                    postdata = {}
                    try:
                        if method == 'GET' or method == 'DELETE':
                            for arg in endpoint['args']:
                                if str(endpoint['args'][arg]["required"]) == "True":
                                    if endpoint['args'][arg]['type'] == 'string':
                                        if str(arg) == 'url':
                                            finalurl = finalurl + '&' + arg + '=' + oob
                                        else:
                                            finalurl = finalurl + '&' + arg + '=view'
                                    else:
                                        finalurl = finalurl + '&' + arg + '=1'
                            response = requests.get(finalurl, headers=self.header,verify=self.ssl,proxies=self.proxy)
                        if method == 'PATCH' or method == 'POST' or method == 'PUT':
                            for arg in endpoint['args']:
                                if str(endpoint['args'][arg]["required"]) == "True":
                                    if endpoint['args'][arg]['type'] == 'integer':
                                        y = {arg: 1}
                                    elif str(arg) == 'url':
                                        y = {arg: oob}
                                    else:
                                        y = {arg: "view"}
                                    postdata.update(y)
                        if method == 'GET':
                            response = requests.get(finalurl, headers=self.header,verify=self.ssl,proxies=self.proxy)
                        if method == 'DELETE':
                            response = requests.delete(finalurl, headers=self.header,verify=self.ssl,proxies=self.proxy)
                        if method == 'POST':
                            response = requests.post(finalurl, headers=self.header,verify=self.ssl,proxies=self.proxy, json=postdata)
                        if method == 'PATCH':
                            response = requests.patch(finalurl, headers=self.header,verify=self.ssl,proxies=self.proxy, json=postdata)
                        if method == 'PUT':
                            response = requests.put(finalurl, headers=self.header,verify=self.ssl,proxies=self.proxy, json=postdata)

                        self.output(method, finalurl, response.status_code)
                    except KeyboardInterrupt:
                        return
                    except Exception:
                        # print(traceback.format_exc())
                        pass


    def main(self,target):
        # print(5)
        # banner()
        global url, oob, media, posts, users, postsflag, mediaflag, usersflag
        url = target["url"].strip('/ ') + '/wp-json'
        # print(1)
        self.ssl = target["ssl"]
        # print(2)
        header = target["header"]
        # print(3)
        proxy = target["proxy"]


        self.header, self.proxy = ReqSet(header=header, proxy=proxy)

        oob = 'default-oob-url'
        postsflag = False
        usersflag = False
        mediaflag = False
        choose = int(input(Fore.BLUE + f'[1] 直接扫描目标\n[2] 使用您提供的带外URL/Dnslog填充获取的端点中的每个“url”参数\n[3] 仅检查媒体/图像(media/images)端点中的问题\n[4] 仅检查用户端点中的问题\n[5] 仅检查 post 端点中的问题\n{Fore.LIGHTYELLOW_EX+">>> Num: "}'))
        if choose == 1:
            pass
        elif choose == 2:
            ck_url = input(Fore.YELLOW + 'DnsLog/Url: ')
            oob = ck_url
        elif choose == 3:
            mediaflag = True
        elif choose == 4:
            usersflag = True
        elif choose == 5:
            postsflag = True
        else:
            print(Fore.RED + '[!] 输入有误！！！！！！')
            return
        media = 1
        posts = 1
        users = 1
        self.run()