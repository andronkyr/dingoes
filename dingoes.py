#!/usr/bin/env python
#
# DiNgoeS: Compare anti-malware and phishing filtering DNS services
# Author: https://twitter.com/gszathmari
#

import os
import time
import argparse
import signal
from pyfiglet import Figlet
from halo import Halo
from sys import exit
from dingoes.hphosts import HpHostsFeed
from dingoes.report import Report
from dingoes.confparser import ConfParse, ConfParseFeed
from dingoes.feed_parsers import preprocess
from datetime import datetime

import logging

def print_banner():
    """Print welcome banner

    """
    figlet = Figlet(font='slant')
    banner = figlet.renderText('DiNgoeS')
    print(banner)
    print("[+] 2017 CryptoAUSTRALIA - https://cryptoaustralia.org.au\n")

def get_args():
    """Get command line arguments

    """
    epoch_time = int(time.time())
    report_filename = "report_{}_{}.csv".format(time.strftime("%Y-%m-%d_%H%M"), epoch_time)
    parser = argparse.ArgumentParser(
        description='Compare DNS server responses.',formatter_class=argparse.MetavarTypeHelpFormatter)
    parser.add_argument('-o', type=str, default=report_filename, help='Report file name')
#    parser.add_argument('-c', type=str, help='hpHosts feed (Default: PSH)', choices=['PSH', 'EMD', 'EXP'], default='PSH')
    parser.add_argument('-n', type=int, help='Number of domains to test (Default: 500)', default=500)
    parser.add_argument('-s', type=int, help='Shell type: set to 1 if spinner errors occur (default: 0)', default=0)
    parser.add_argument('-u', type=str, help='Update (download and preprocess) Threat Intelligence feeds', default = 'y')
    args = parser.parse_args()
    return args

def main():
    print_banner()
    args = get_args()
    if( args.s == 0 ):
        spinner = Halo(spinner='dots')
    try:
        if (args.s == 0):
           spinner.start(text='Parsing configuration file')
        config = ConfParse()
        if (args.s == 0):
            spinner.succeed()
    except Exception as e:
        if(args.s == 0):
            spinner.fail()
        print("\n\nError parsing configuration file: {}\n".format(e))
        exit(1)

    try:
        if (args.s == 0):
            spinner.start(text='Parsing threat intelligence feed configuration file')
        configTI = ConfParseFeed()
        if (args.s == 0):
            spinner.succeed()
    except Exception as e:
        if(args.s == 0):
            spinner.fail()
        print("\n\nError parsing configuration file: {}\n".format(e))
        exit(1)


    if (args.u == 'y'):
        try:
            print('[+] Preprocessing threat intelligence feeds')
            preprocess(configTI)
        except Exception as e:
            if(args.s == 0):
                spinner.fail()
            print("\n\nError parsing threat intelligence feeds: {}\n".format(e))
            exit(1)
    # try:
    #     if(args.s == 0):
    #         spinner.start(text="Retrieving hpHosts feed: {}".format(args.c))
    #     hphosts_feed = HpHostsFeed(args.c)
    #     hphosts_feed = []
    #     if(args.s == 0):
    #         spinner.succeed()
    # except Exception as e:
    #     if(args.s == 0):
    #         spinner.fail()
    #     print("\n\nError retrieving hpHosts feed: {}\n".format(e))
    #     exit(1)
    # Create object and load in the retrieved values from above
    for feed in configTI.confvalues.keys():
        report_filename = "{}-{}.csv".format(datetime.now().strftime("%d.%m.%Y"),feed)
        domains = []
        with open("input/"+feed,"r") as f:
            for line in f.readlines():
                domains.append(line.strip())
        report = Report(domains, report_filename, config)
        # Process results
        print("\n [+] Processing feed from {}".format(feed))
        print(" [+] Processing {} entries, this may take a while:\n".format(args.n))
        report.write_results(args.n)
        print("\n\n [+] Great success.\n")
        # Plot stats histogram
        if(args.s==0):
            report.print_stats_diagram(args.n)
        print("\nDetailed report is available in {}\n".format(report_filename))

def signal_handler(signal, frame):
    print('\n\nYou pressed Ctrl+C!\n')
    os._exit(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main()
