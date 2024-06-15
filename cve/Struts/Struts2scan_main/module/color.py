#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from colorama import init
from colorama import Fore,Style
init(autoreset=True)

#Style字体格式: DIM 暗, NORMAL 正常, BRIGHT 亮, RESET_ALL

#Fore字体颜色: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.

#Back背景颜色: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.

class Colored:
    @staticmethod
    def cyan(s):
        return Style.BRIGHT + Fore.CYAN    + s + Fore.RESET + Style.RESET_ALL
    @staticmethod
    def magenta(s):
        return Style.BRIGHT + Fore.MAGENTA + s + Fore.RESET + Style.RESET_ALL
    @staticmethod
    def red(s):
        return Style.BRIGHT + Fore.RED     + s + Fore.RESET + Style.RESET_ALL
    @staticmethod
    def green(s):
        return Style.BRIGHT + Fore.GREEN   + s + Fore.RESET + Style.RESET_ALL
        
color = Colored()
