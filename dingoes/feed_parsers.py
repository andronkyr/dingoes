import os
import requests
import zipfile
import re

def is_ip(ip):
    return re.match(r'^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$', ip)

def download(name,url):
    data = requests.get(url) 
    with open('input_raw/' + name, 'wb') as f:
        f.write(data.content)

def output(name,domains):
    with open('input/' + name, 'w') as f:
        f.write("\n".join(domains))



class parse_urlhaus():
    def process():
        domains = []
        with zipfile.ZipFile("input_raw/urlhaus", 'r') as zip_urlhaus:
            zip_urlhaus.extractall("input_raw/")
        with open("input_raw/csv.txt","r") as f:
            for line in f.readlines():
                if line.startswith("#"):
                    continue
                else:
                    domain = line.split(',')[2].split("://")[1].split("/")[0] 
                    if (":") in domain:
                        domain = domain.split(':')[0]
                    if domain not in domains and not is_ip(domain):
                        domains.append(domain)
        return (domains)


class parse_sans():
    def process():
        domains = []
        with open("input_raw/sans","r") as f:
            for line in f.readlines():
                if line.startswith("#"):
                    continue
                else:
                    if line not in domains:
                        domains.append(line.strip())
            return(domains)



class parse_bambenek():
    def process():
        domains = []
        with open("input_raw/bambenek","r") as f:
            for line in f.readlines():
                if line.startswith("#"):
                    continue
                else:
                    domain = line.split(',')[0].strip()
                    if domain not in domains:
                        domains.append(domain)
            return(domains)



action_mapping = {
    "bambenek": parse_bambenek,
    "urlhaus": parse_urlhaus,
    "sans": parse_sans
}

def preprocess (config):

    if not os.path.exists('input_raw'):
        os.makedirs('input_raw')
    if not os.path.exists('input'):
        os.makedirs('input')

    feeds = config.confvalues
    feed_names = config.confvalues.keys()

    for current in feed_names:
        print("[+] Downloading {} feed".format(current))
        download(current, feeds[current]["source"] )
        print("[+] Processing {} feed".format(current))
        domains = action_mapping[current].process()
        print("[+] Exporting domains from {} feed".format(current))
        output(current,domains)
