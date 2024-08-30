#!/user/bin/env python3
# -*- coding: utf-8 -*-
import yaml


class ConfigLoader:
    def __init__(self):
        self.config = self._load_config()
        self.values = self._extract_values()
    def _load_config(self):
        with open("./set/config.yaml", "r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    def get_values(self):
        return self.values
    def _extract_values(self):
        values = {
            "version": self.config['version'],
            "ua": self.config['default-settings']['ua'],
            "ip": self.config['default-settings']['ip'],
            "domain": self.config['default-settings']['domain'],
            "url": self.config['default-settings']['url'],
            "port": self.config['default-settings']['port'],
            "cmd": self.config['default-settings']['cmd'],
            "threads": self.config['default-settings']['threads'],
            "cookie": self.config['default-settings']['cookie'],
            "ssl": self.config['default-settings']['ssl'],
            "rhost": self.config['rebound-settings']['rhost'],
            "rport": self.config['rebound-settings']['rport'],
            "lhost": self.config['rebound-settings']['lhost'],
            "lport": self.config['rebound-settings']['lport'],
            "proxy": self.config['proxy-settings']['proxy'],
            "file": self.config['file-settings']['file'],
            "timeout": self.config['default-settings']['timeout'],
            "censys_API": self.config['api-keys']['censys']['api'],
            "censys_auth": self.config['api-keys']['censys']['auth'],
            "censys_Secret": self.config['api-keys']['censys']['secret'],
            "shodan-api": self.config['api-keys']['shodan-api'],
            "ceye-dns": self.config['api-keys']['ceye-dns'],
            "ceye-api": self.config['api-keys']['ceye-api'],
            "yaml-pocs-dir": self.config['yaml-pocs-dir'],
            "api-list": self.config['securitytrails-keys']['api-list'],
            "batch-work-file": self.config['file-settings']['batch-work-file'],
            "virustotal-api": self.config['api-keys']['virustotal-api'],
            "dnsdump-csrftoken": self.config['api-keys']['dnsdump-csrftoken'],
            "fofa_email": self.config['api-keys']['fofa']['email'],
            "fofa_key": self.config['api-keys']['fofa']['key'],
            "yt-key": self.config['api-keys']['yt-key'],
            "viewdns-key": self.config['api-keys']['viewdns-key'],
            "fullhunt-api": self.config['api-keys']['fullhunt-api'],
            "zoomeye-key": self.config['api-keys']['zoomeye-key'],
            "quake-key": self.config['api-keys']['quake-key'],
            "binaryedge-key": self.config['api-keys']['binaryedge-key'],
            "whoisxmlapi-key": self.config['api-keys']['whoisxmlapi-key'],
            "cmd5_key": self.config['cmd5']['key'],
            "cmd5_mail": self.config['cmd5']['mail'],
            "hunter-how-key": self.config['api-keys']['hunter-how-key'],
            "daydaymap-key": self.config['api-keys']['daydaymap-key'],
        }
        return values
