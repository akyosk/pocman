#! /usr/bin/python3
# -*- coding: utf-8 -*-
from pub.com.outprint import OutPrintInfo
from rich.progress import Progress
import random
import string
# 社工密码
class PwdsDomain():
    def __init__(self, url=None, counts=50000):
        self._url = url
        self._counts = counts
    def _split_and_recombine(self, domain, min_length=6, max_length=10):
        domain_parts = [domain[i: j] for i in range(len(domain)) for j in range(i + 1, len(domain) + 1) if '.' not in domain[i:j]]
        random.shuffle(domain_parts)

        password = ''
        while len(password) < min_length:
            password += random.choice(domain_parts)
            if len(password) > max_length:
                password = password[:max_length]
                break
        uppercase_letter = random.choice(string.ascii_uppercase)
        special_char = random.choice(['_', '*', '@'])

        insert_pos_upper = random.randint(0, len(password))
        password = password[:insert_pos_upper] + uppercase_letter + password[insert_pos_upper:]

        insert_pos_special = random.randint(0, len(password))
        password = password[:insert_pos_special] + special_char + password[insert_pos_special:]

        return password


    def _passwd(self, domain, min_length=6, max_length=10):
        # print(domain)
        passwords = set()

        # with tqdm(total=self._counts, desc="随机字典生成进度", bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as progress_bar:
        with Progress(transient=True) as progress:
            task = progress.add_task("[cyan]生成密码中...",total=self._counts)
            while len(passwords) < self._counts:
                # 随机拆分重组域名
                password = self._split_and_recombine(domain, min_length, max_length)
                if len(password) <= max_length and password not in passwords:
                    passwords.add(password)
                    progress.update(task,advance=1)
        return list(passwords)[:self._counts]


    def _save_passwords_to_file(self, passwords):
        with open("./result/domainPassword.txt", "w") as f:
            for password in passwords:
                f.write(password + '\n')
                # f.flush()


    def main(self,result):
        OutPrintInfo("PASSWORD","开始根据域名生成随机密码......")
        self._url = result["domain"].strip('/')
        self._counts = int(result["counts"])
        if '://' in self._url:
            domain = self._url.split('/')[2].split('.')[0] + self._url.split('/')[2].split('.')[1]
        else:
            domain = self._url
        passwords = self._passwd(domain)
        self._save_passwords_to_file(passwords)
        OutPrintInfo("PASSWORD",f"已将 {len(passwords)} 个密码保存到result/pwds.txt 文件中。")
        OutPrintInfo("PASSWORD","若没有生成文件可尝试结束任务查看!")
