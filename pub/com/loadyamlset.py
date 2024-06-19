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
            "ua": self.config['default_settings']['ua'],
            "ip": self.config['default_settings']['ip'],
            "domain": self.config['default_settings']['domain'],
            "url": self.config['default_settings']['url'],
            "port": self.config['default_settings']['port'],
            "cmd": self.config['default_settings']['cmd'],
            "threads": self.config['default_settings']['threads'],
            "cookie": self.config['default_settings']['cookie'],
            "ssl": self.config['default_settings']['ssl'],
            "rhost": self.config['rebound_settings']['rhost'],
            "rport": self.config['rebound_settings']['rport'],
            "lhost": self.config['rebound_settings']['lhost'],
            "lport": self.config['rebound_settings']['lport'],
            "proxy": self.config['proxy_settings']['proxy'],
            "file": self.config['file_settings']['file'],
            "timeout": self.config['default_settings']['timeout'],
            "censys_API": self.config['api_keys']['censys']['api'],
            "censys_auth": self.config['api_keys']['censys']['auth'],
            "censys_Secret": self.config['api_keys']['censys']['secret'],
            "shodan_api": self.config['api_keys']['shodan_api'],
            "ceye_dns": self.config['api_keys']['ceye_dns'],
            "ceye_api": self.config['api_keys']['ceye_api'],
            "yaml_pocs_dir": self.config['yaml_pocs_dir'],
            "api_list": self.config['securitytrails_keys']['api_list'],
            "batch_work_file": self.config['file_settings']['batch_work_file'],
            "virustotal_api": self.config['api_keys']['virustotal_api'],
            "dnsdump_csrftoken": self.config['api_keys']['dnsdump_csrftoken'],
            "fofa_email": self.config['api_keys']['fofa']['email'],
            "fofa_key": self.config['api_keys']['fofa']['key'],
            "yt_key": self.config['api_keys']['yt_key'],
            "viewdns_key": self.config['api_keys']['viewdns_key'],
            "fullhunt_api": self.config['api_keys']['fullhunt_api'],
            "zoomeye_key": self.config['api_keys']['zoomeye_key'],
            "quake_key": self.config['api_keys']['quake_key'],
            "binaryedge_key": self.config['api_keys']['binaryedge_key'],
            "whoisxmlapi_key": self.config['api_keys']['whoisxmlapi_key'],
            "cmd5_key": self.config['cmd5']['key'],
            "cmd5_mail": self.config['cmd5']['mail'],
            "hunter_how_key": self.config['api_keys']['hunter_how_key'],
            "daydaymap_key": self.config['api_keys']['daydaymap_key']
        }
        return values
