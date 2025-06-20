#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This code is based on the following:
# https://github.com/noise-lab/dns-measurement/blob/master/src/docker/run.py

import argparse
import os.path
import sys
import time
from datetime import datetime
from selenium.webdriver import FirefoxOptions, FirefoxProfile, Firefox


# overwrite /etc/resolv.conf
# from
# nameserver 127.0.0.11
# options ndots:0
# to
# nameserver [resolver_ip]
# options ndots:0
def overwrite_resolv_conf(resolver_ip: str):
    with open('/etc/resolv.conf', 'w') as f:
        f.write('nameserver ' + resolver_ip + '\n')
        f.write('options ndots:0\n')

def initFireFoxOptions():
    options = FirefoxOptions()
    options.log.level = "trace"
    options.headless = True
    # This is needed to avoid accessing web pages when DANE validation fails.
    options.accept_insecure_certs = False
    options.add_argument('-devtools')
    # use the default DNS resolver, not use DoH.
    options.set_preference('network.trr.mode', 0)
    return options

def initFireFoxProfile(dane: bool, dane_proxy_host: str, nondane_proxy_host: str):
    profile = FirefoxProfile()

    if dane:
        proxy_host = dane_proxy_host
        proxy_port = 8080
    else:
        proxy_host = nondane_proxy_host
        proxy_port = 8081
        
    if proxy_host: # Only set proxy if a host is provided
        profile.set_preference("network.proxy.type", 1)
        profile.set_preference("network.proxy.http", proxy_host)
        profile.set_preference("network.proxy.http_port", proxy_port)
        profile.set_preference("network.proxy.ssl", proxy_host)
        profile.set_preference("network.proxy.ssl_port", proxy_port)
    return profile

def initFireFoxDriver(options: FirefoxOptions, profile: FirefoxProfile):
    firefox_binary_path = "/opt/firefox/firefox-bin"
    driver = Firefox(
        options=options,
        firefox_profile=profile,
        firefox_binary=firefox_binary_path,
        )
    driver.set_page_load_timeout(30)
    return driver

# In the Background, Native messaging is used to collect HAR files.
# https://github.com/noise-lab/dns-measurement/blob/master/src/docker/har_catcher.py
# https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
def har_file_ready(file_path: str):
    return os.path.exists(file_path + ".ready")

# How to run:
# python3 custom_run.py https://www.example.com/ --resolver_ip 1.1.1.1 --proxy_host letsdane-www.example.com --dane --cache
def main():
    parser = argparse.ArgumentParser(
        prog='firefox-har',
        description='Load a web page and return the HAR file'
    )
    parser.add_argument('website', type=str, help='The website to load')
    parser.add_argument('-ri', '--resolver_ip', type=str, help='The IP address of the resolver to use')
    parser.add_argument('-dph', '--dane_proxy_host', type=str, help='The host name of the DANE proxy to use')
    parser.add_argument('-ndph', '--nondane_proxy_host', type=str, help='The host name of the non-DANE proxy to use')
    parser.add_argument('--timeout', type=int, default=30, help='The maximum time to wait for the page to load')
    parser.add_argument('--dane', action='store_true', help='Enable DANE validation')
    parser.add_argument('--fill_cache_only', action='store_true', help='Only fill the cache and exit')
    args = parser.parse_args()

    # This allow FireFox to use elf-hosted DNS resolver.
    if args.resolver_ip:
        overwrite_resolv_conf(args.resolver_ip)

    options = initFireFoxOptions()
    profile = initFireFoxProfile(args.dane, args.dane_proxy_host, args.nondane_proxy_host)
    profile.set_preference('devtools.toolbox.selectedTool', 'netmonitor')
    driver = initFireFoxDriver(options, profile)

    har_addon_path = "/home/seluser/measure/harexporttrigger-0.6.2-fx.xpi"
    driver.install_addon(har_addon_path, temporary=True)

    # Access website to cache RRset in the unbound before the measurement.
    if args.fill_cache_only:
        driver.get(args.website)
        driver.quit()
        return

    # Make a page load
    started = datetime.now()
    driver.get(args.website)

    har_file = "/home/seluser/measure/har.json"

    while (datetime.now() - started).total_seconds() < args.timeout and not har_file_ready(har_file):
        time.sleep(1)

    # Once the HAR is on disk in the container, write it to stdout so the host machine can get it
    if har_file_ready(har_file):
        with open(har_file, 'rb') as f:
            sys.stdout.buffer.write(f.read())

    driver.quit()

if __name__ == '__main__':
    main()
