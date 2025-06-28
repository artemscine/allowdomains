#!/usr/bin/env python3.10

import tldextract
import urllib.request
import re
from pathlib import Path
import json
import os
import subprocess
import fnmatch

# ---------------------------------------------
# Списки доменов для фильтрации
# ---------------------------------------------
ExcludeServices = {"telegram.lst", "cloudflare.lst", "google_ai.lst", "google_play.lst", 'hetzner.lst', 'ovh.lst', 'amazon.lst'}

# Общие списки исключаемых доменов для lst-файлов
removeDomains = {
    'google.com', 'googletagmanager.com', 'github.com', 'githubusercontent.com',
    'githubcopilot.com', 'microsoft.com', 'cloudflare-dns.com', 'parsec.app'
}
removeDomainsMikrotik = removeDomains | {'showip.net'}
removeDomainsKvas = removeDomains | {'t.co', 'ua'}

# ---------------------------------------------
# Список шаблонов для выборочной фильтрации russia_inside
# ---------------------------------------------
removeRussiaInsideSRS = [
    '*youtube*',
    '*tiktok*',
    '*ytimg*',
    'googlevideo.com',
    'yt3.ggpht.com',
    'yt4.ggpht.com',
    'jnn-pa.googleapis.com',
    'yt-video-upload.l.google.com',
]

# ---------------------------------------------
# Пути к исходным данным
# ---------------------------------------------
rusDomainsInsideCategories = 'Categories'
rusDomainsInsideServices = 'Services'
rusDomainsOutsideSrc = 'src/Russia-domains-outside.lst'
uaDomainsSrc = 'src/Ukraine-domains-inside.lst'

# ---------------------------------------------
# Подсети
# ---------------------------------------------
DiscordSubnets = 'Subnets/IPv4/discord.lst'
MetaSubnets = 'Subnets/IPv4/meta.lst'
TwitterSubnets = 'Subnets/IPv4/twitter.lst'
TelegramSubnets = 'Subnets/IPv4/telegram.lst'
CloudflareSubnets = 'Subnets/IPv4/cloudflare.lst'
HetznerSubnets = 'Subnets/IPv4/hetzner.lst'
OVHSubnets = 'Subnets/IPv4/ovh.lst'
AmazonSubnets = 'Subnets/IPv4/amazon.lst'

# ---------------------------------------------
# Функция фильтрации для russia_inside
# ---------------------------------------------
def filter_russia(domains):
    """Удаляет из списка domains любые, подходящие под шаблоны removeRussiaInsideSRS."""
    return [d for d in domains if not any(fnmatch.fnmatch(d, pat) for pat in removeRussiaInsideSRS)]

# ---------------------------------------------
# Генерация raw и dnsmasq списков
# ---------------------------------------------

def raw(src, out):
    domains = set()
    files = []
    if isinstance(src, list):
        for dir_path in src:
            path = Path(dir_path)
            if path.is_dir():
                files.extend(f for f in path.glob('*') if f.name not in ExcludeServices)
            elif path.is_file() and path.name not in ExcludeServices:
                files.append(path)

    for f in files:
        with open(f, 'r', encoding='utf-8') as infile:
            for line in infile:
                tld = tldextract.extract(line.strip())
                if tld.suffix:
                    if re.search(r'[^а-я\-]', tld.domain):
                        domains.add(tld.fqdn)
                    elif not tld.domain:
                        domains.add('.' + tld.suffix)

    domains = sorted(domains)
    with open(f'{out}-raw.lst', 'w', encoding='utf-8') as file:
        for name in domains:
            file.write(f'{name}\n')


def dnsmasq(src, out, remove=removeDomains):
    domains = set()
    files = []
    if isinstance(src, list):
        for dir_path in src:
            path = Path(dir_path)
            if path.is_dir():
                files.extend(f for f in path.glob('*') if f.name not in ExcludeServices)
            elif path.is_file() and path.name not in ExcludeServices:
                files.append(path)
    for f in files:
        with open(f, 'r', encoding='utf-8') as infile:
            for line in infile:
                tld = tldextract.extract(line.strip())
                if tld.suffix:
                    if re.search(r'[^а-я\-]', tld.domain):
                        domains.add(tld.fqdn)
                    elif not tld.domain:
                        domains.add('.' + tld.suffix)
    domains = sorted(domains - remove)
    with open(f'{out}-dnsmasq.lst', 'w', encoding='utf-8') as file:
        for name in domains:
            file.write(f'domain=/{name}/#')

# ---------------------------------------------
# SRS-генерация
# ---------------------------------------------

def domains_from_file(filepath):
    domains = []
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            for line in file:
                d = line.strip()
                if d:
                    domains.append(d)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    return domains


def generate_srs_domains(domains, output_name,
                         output_json_directory='JSON', compiled_output_directory='SRS'):
    os.makedirs(output_json_directory, exist_ok=True)
    os.makedirs(compiled_output_directory, exist_ok=True)

    data = {
        "version": 3,
        "rules": [{"domain_suffix": domains}]
    }

    json_path = os.path.join(output_json_directory, f"{output_name}.json")
    srs_path = os.path.join(compiled_output_directory, f"{output_name}.srs")

    with open(json_path, 'w', encoding='utf-8') as jf:
        json.dump(data, jf, indent=4)
    print(f"JSON generated: {json_path}")

    try:
        subprocess.run(["sing-box", "rule-set", "compile", json_path, "-o", srs_path], check=True)
        print(f"SRS compiled: {srs_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error compiling {json_path}: {e}")


def generate_srs_for_categories(directories,
                                output_json_directory='JSON', compiled_output_directory='SRS'):
    os.makedirs(output_json_directory, exist_ok=True)
    os.makedirs(compiled_output_directory, exist_ok=True)

    exclude = {"meta", "twitter", "discord", "telegram", "hetzner", "ovh", "amazon"}
    for d in directories:
        for fname in os.listdir(d):
            name, ext = os.path.splitext(fname)
            if ext != '.lst' or any(k in name for k in exclude):
                continue
            path = os.path.join(d, fname)
            domains = [line.strip() for line in open(path, 'r', encoding='utf-8') if line.strip()]

            data = {"version": 3, "rules": [{"domain_suffix": domains}]}
            json_path = os.path.join(output_json_directory, f"{name}.json")
            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(data, jf, indent=4)
            print(f"JSON generated: {json_path}")

    # Компиляция всех JSON
    for jf in os.listdir(output_json_directory):
        if jf.endswith('.json'):
            jp = os.path.join(output_json_directory, jf)
            sp = os.path.join(compiled_output_directory, f"{os.path.splitext(jf)[0]}.srs")
            try:
                subprocess.run(["sing-box", "rule-set", "compile", jp, "-o", sp], check=True)
                print(f"SRS compiled: {sp}")
            except subprocess.CalledProcessError as e:
                print(f"Error compiling {jp}: {e}")

# ---------------------------------------------
# Main
# ---------------------------------------------
if __name__ == '__main__':
    Path("Russia").mkdir(parents=True, exist_ok=True)
    Path("Ukraine").mkdir(parents=True, exist_ok=True)

    # Скачиваем украинские списки
    urllib.request.urlretrieve("https://uablacklist.net/domains.txt", "uablacklist-domains.lst")
    urllib.request.urlretrieve("https://raw.githubusercontent.com/zhovner/zaborona_help/master/config/domainsdb.txt", "zaboronahelp-domains.lst")

    # Генерация lst-файлов
    inside_lists = [rusDomainsInsideCategories, rusDomainsInsideServices]
    outside_lists = [rusDomainsOutsideSrc]
    ua_lists = ['uablacklist-domains.lst', 'zaboronahelp-domains.lst', uaDomainsSrc]

    raw(inside_lists, 'Russia/inside')
    dnsmasq(inside_lists, 'Russia/inside', removeDomains)
    # Другие генераторы lst-файлов: clashx, kvas, mikrotik_fwd

    raw(outside_lists, 'Russia/outside')
    dnsmasq(outside_lists, 'Russia/outside', removeDomains)
    # ...

    raw(ua_lists, 'Ukraine/inside')
    dnsmasq(ua_lists, 'Ukraine/inside', removeDomains)
    # ...

    # SRS-генерация доменов
    russia_inside = domains_from_file('Russia/inside-raw.lst')
    # Применяем фильтрацию только для russia_inside
    russia_inside = filter_russia(russia_inside)
    generate_srs_domains(russia_inside, 'russia_inside')

    russia_outside = domains_from_file('Russia/outside-raw.lst')
    generate_srs_domains(russia_outside, 'russia_outside')

    ukraine_inside = domains_from_file('Ukraine/inside-raw.lst')
    generate_srs_domains(ukraine_inside, 'ukraine_inside')

    # SRS по категориям и сервисам без фильтрации
    generate_srs_for_categories(['Categories', 'Services'])
    # Добавьте аналогичные вызовы для подсетей или комбинированных SRS
