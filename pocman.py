#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import readline  # 不可删
from pub.libs.main import PocMain
import argparse
from rich.console import Console

class RichHelpFormatter(argparse.HelpFormatter):
    def format_help(self):
        console = Console()
        help_message = super().format_help()
        console.print(help_message, style="blue")
        return ""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='PocMain Script with Optional Rich Support',
        formatter_class=RichHelpFormatter
    )

    parser.add_argument('--rich', action='store_true', help='Enable rich output')
    args = parser.parse_args()

    if args.rich:
        from pub.com import outprint
        outprint.rich_flag = True

    try:
        PocMain().main()
    except KeyboardInterrupt:
        pass
