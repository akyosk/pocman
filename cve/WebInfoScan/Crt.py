#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import dns.resolver
import feedparser
import logging
import requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoErr
from rich.prompt import Prompt
base_url = "https://crt.sh/atom?q=%25.{}"



class CERTScan:
    def get_rss_for_domain(self, domain):
        # print(domain)
        """Pull the domain identity information from CERT.sh"""
        OutPrintInfo("CERT",f"Retrieving information about [b bright_red]{domain}[/b bright_red] from CERT.sh...")
        results_raw = requests.get(base_url.format(domain)).content
        results_entries = feedparser.parse(results_raw)["entries"]
        OutPrintInfo("CERT","Retrieval of info done.")
        return results_entries

    def parse_entries(self, identity, results_list):
        entries_raw = None
        """This is pretty gross, but necessary when using CERT.sh: parse the contents of the summary
        entry and return individual host names."""
        line_breaks = ["<br>", "<br />"]
        for cur_break in line_breaks:
            if cur_break in identity["summary"]:
                entries_raw = identity["summary"][:identity["summary"].index(cur_break)].replace("&nbsp;", "\n")
        entries = entries_raw.split("\n")
        for entry in entries:
            trimmed_entry = entry.strip()
            stringified_entry = str(trimmed_entry)
            results_list.append(stringified_entry)

    def format_entries(self, results, do_resolve_dns):
        final_results = None
        """Sort and deduplicate hostnames and, if DNS resolution is turned on, resolve hostname"""
        sorted_results = sorted(set(results))
        if do_resolve_dns:
            try:
                OutPrintInfo("CERT","DNS resolution turned on.")
                final_results = []
                for cur_result in sorted_results:
                    if "*" not in cur_result:
                        OutPrintInfo("CERT",f"Resolving {cur_result}...")
                        try:
                            ip_addresses = dns.resolver.query(cur_result)
                            for ip_address in ip_addresses:
                                final_results.append("{}\t{}".format(cur_result, ip_address))
                        except dns.resolver.NoAnswer:
                            final_results.append(cur_result)
                        OutPrintInfo("CERT","... done.")
                    else:
                        final_results.append(cur_result)
            except Exception as e:
                OutPrintInfoErr(str(e))
        else:
            final_results = sorted_results
        return final_results

    def main(self, target):
        resolve_dns = False
        domains = target['domain']
        if "://" in domains:
            OutPrintInfoErr('只支持域名格式')
            return
        OutPrintInfo("1","直接扫描搜索输入的域名")
        OutPrintInfo("2","对主机名执行 DNS 查找")
        OutPrintInfo("3","打印更多信息，例如 RSS 和 DNS 检索的状态")
        try:
            choose = int(Prompt.ask("[b blue]输入需要执行的模块[/b blue]"))
            # choose = int(input(Fore.YELLOW + "输入需要执行的模块: "))
        except Exception as e:
            OutPrintInfoErr(e)
            return
        if choose == 2:
            resolve_dns = True
        if choose == 3:
            logging.basicConfig(level=logging.INFO)

        results = []
        # for cur_domain in domains:
        domain = domains.strip()
        results_entries = self.get_rss_for_domain(domain)
        for cur_entry in results_entries:
            self.parse_entries(cur_entry, results)
        final_results = self.format_entries(results, resolve_dns)
        for i in final_results:
            # print(i)
            OutPrintInfo("CERT",f"{i.strip()}")
