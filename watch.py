import pymongo
import os
import subprocess
import requests
import json
from discord import SyncWebhook
from datetime import date,datetime
from datetime import datetime as td
import datetime
import schedule
import time
import hashlib
import traceback


# TODO: Add your Discord webhook URLs as environment variables before running.
new_sub_webhook = SyncWebhook.from_url(os.environ["NEW_SUB_WEBHOOK_URL"])
new_res_webhook = SyncWebhook.from_url(os.environ["NEW_RES_WEBHOOK_URL"])
http_change_webhook = SyncWebhook.from_url(os.environ["HTTP_CHANGE_WEBHOOK_URL"])
new_http_webhook = SyncWebhook.from_url(os.environ["NEW_HTTP_WEBHOOK_URL"])
nuclei_webhook = SyncWebhook.from_url(os.environ["NUCLEI_WEBHOOK_URL"])
other_webhook = SyncWebhook.from_url(os.environ["OTHER_WEBHOOK_URL"])

# TODO: Add your Telegram bot tokens and chat ID as environment variables before running.
telegram_chat_id = os.environ["TELEGRAM_CHAT_ID"]
new_sub_telegram = os.environ["NEW_SUB_TELEGRAM_TOKEN"]
new_res_telegram = os.environ["NEW_RES_TELEGRAM_TOKEN"]
http_change_telegram = os.environ["HTTP_CHANGE_TELEGRAM_TOKEN"]
new_http_telegram = os.environ["NEW_HTTP_TELEGRAM_TOKEN"]
nuclei_telegram = os.environ["NUCLEI_TELEGRAM_TOKEN"]
other_telegram = os.environ["OTHER_TELEGRAM_TOKEN"]




mongo = pymongo.MongoClient("mongodb://localhost:27017/")

def tsubsendmessage(domain, sub, provider, action):
    msg = f"========== ***New {domain} {action}*** ===========\n"
    msg += "Subdomain : "
    msg += f"""```
{sub}```"""
    msg += "Date : "
    msg += f"""```
{str(date.today())}```"""
    msg += "Resource : "
    msg += f"""```
{provider}```"""
    requests.get(f"https://api.telegram.org/bot{new_sub_telegram}/sendMessage?chat_id={telegram_chat_id}&text={msg}&parse_mode=MarkDown")

def tsubressendmessage(domain, sub, provider, action):
    msg = f"========== ***New {domain} {action}*** ===========\n"
    msg += "Subdomain : "
    msg += f"""```
{sub}```"""
    msg += "Date : "
    msg += f"""```
{str(date.today())}```"""
    msg += "Resource : "
    msg += f"""```
{provider}```"""
    requests.get(f"https://api.telegram.org/bot{new_res_telegram}/sendMessage?chat_id={telegram_chat_id}&text={msg}&parse_mode=MarkDown")
    new_res_webhook.send(msg)

def thttpxsendmessage(subdomain, old, new, action):
    msg = f"========== ***HTTP Change {subdomain} {action}*** ===========\n"
    msg += "OLD Data : "
    msg += f"""```
{old}```"""
    msg += "New Data : "
    msg += f"""```
{new}```"""
    msg += "Date : "
    msg += f"""```
{str(date.today())}```"""
    requests.get(f"https://api.telegram.org/bot{http_change_telegram}/sendMessage?chat_id={telegram_chat_id}&text={msg}&parse_mode=MarkDown")


def subsendmessage(domain, sub, provider, action):
    msg = f"========== ***New {domain} {action}*** ===========\n"
    msg += ">>> Subdomain : "
    msg += f"""```arm
{sub}```"""
    msg += "Date : "
    msg += f"""```arm
{str(date.today())}```"""
    msg += "Resource : "
    msg += f"""```arm
{provider}```"""
    new_sub_webhook.send(msg)

def subressendmessage(domain, sub, provider, action):
    msg = f"========== ***New {domain} {action}*** ===========\n"
    msg += ">>> Subdomain : "
    msg += f"""```arm
{sub}```"""
    msg += "Date : "
    msg += f"""```arm
{str(date.today())}```"""
    msg += "Resource : "
    msg += f"""```arm
{provider}```"""
    new_res_webhook.send(msg)

def httpxsendmessage(subdomain, old, new, action):
    msg = f"========== ***HTTP Change {subdomain} {action}*** ===========\n"
    msg += ">>> OLD Data : "
    msg += f"""```arm
{old}```"""
    msg += "New Data : "
    msg += f"""```arm
{new}```"""
    msg += "Date : "
    msg += f"""```arm
{str(date.today())}```"""
    http_change_webhook.send(msg)

def subfinder():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    subfindersublist = []
    for finderdomain in targets:
        if finderdomain == "":
            continue
        db = mongo[str(finderdomain).replace(".", "-")]
        col = db["all"]
        subfinder = subprocess.getoutput(f"subfinder -d {finderdomain} -all -silent")
        subfinder = subfinder.strip()
        
        for subfindersub in subfinder.split("\n"):
            if str(subfindersub) in targets[finderdomain]['out_of_scope']:
                continue
            exist = col.find_one({"subdomain": subfindersub})
            if str(exist) == "None":
                subfindersublist.append(subfindersub)
                subfinddata = {
                    'subdomain': subfindersub,
                    'date': td.today().strftime('%Y/%m/%d'),
                    'provider': 'Subfinder'
                }
                col.insert_one(subfinddata)
                status = json.loads(open("setting.json","r").read())
                if str(status['sendmessage']['status']) == "enable":
                    subsendmessage(finderdomain, subfindersub, 'Subfinder', 'Subdomain')
                    tsubsendmessage(finderdomain, subfindersub, 'Subfinder', 'Subdomain')
    if len(subfindersublist) > 0:
        if str(status['new_sub_nuclei']['status']) == "enable":
            nuclei(subfindersublist)

def crt():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    crtsublist = []
    for crtdomain in targets:
        if crtdomain == "":
            continue
        db = mongo[str(crtdomain).replace(".", "-")]
        col = db["all"]
        crt = subprocess.getoutput(f"echo \"SELECT ci.NAME_VALUE FROM certificate_and_identities ci WHERE plainto_tsquery('certwatch', '{crtdomain}') @@ identities(ci.CERTIFICATE)\" | psql -t -h crt.sh -p 5432 -U guest certwatch | sed 's/ //g' | egrep \".*.\.{crtdomain}\" | sed 's/*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u")
        crt = crt.strip()
        
        for crtsub in crt.split("\n"):
            if str(crtsub) in targets[crtdomain]['out_of_scope']:
                continue
            if "*." in crtsub:
                continue
            exist = col.find_one({"subdomain": crtsub})
            if str(exist) == "None":
                crtsublist.append(crtsub)
                crtdata = {
                'subdomain': crtsub,
                'date': td.today().strftime('%Y/%m/%d'),
                'provider': 'CRTSH'
            }
                col.insert_one(crtdata)
                status = json.loads(open("setting.json","r").read())
                if str(status['sendmessage']['status']) == "enable":
                    subsendmessage(crtdomain, crtsub, 'CRTSH', 'Subdomain')
                    tsubsendmessage(crtdomain, crtsub, 'CRTSH', 'Subdomain')
    if len(crtsublist) > 0:
        if str(status['new_sub_nuclei']['status']) == "enable":
            nuclei(crtsublist)

def securitytrials():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    # TODO: Add comma-separated SecurityTrails API keys to this environment variable.
    securitytrails_keys = [key.strip() for key in os.environ.get("SECURITYTRAILS_API_KEYS", "").split(",") if key.strip()]
    if not securitytrails_keys:
        raise RuntimeError("SECURITYTRAILS_API_KEYS is not configured")
    apikey = {"securitytrails": securitytrails_keys}
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    securitysublist = []
    for securitydomain in targets:
        apilen = 0
        while True:
            if securitydomain == "":
                continue
            db = mongo[str(securitydomain).replace(".", "-")]
            col = db["all"]
            url = f"https://api.securitytrails.com/v1/domain/{securitydomain}/subdomains?children_only=false&include_inactive=true"
            headers = {
                "accept": "application/json",
                "APIKEY": apikey['securitytrails'][apilen]
            }
            try:
                response = requests.get(url, headers=headers)
            except:
                continue
            try:
                js = json.loads(response.text)
            except:
                continue
            try:
                for securitysub in js['subdomains']:
                    securitysub = securitysub+"."+securitydomain
                    if str(securitysub) in targets[securitydomain]['out_of_scope']:
                        continue
                    
                    exist = col.find_one({"subdomain": securitysub})
                    if str(exist) == "None":
                        securitysublist.append(securitysub)
                        securitydata = {
                        'subdomain': securitysub,
                        'date': td.today().strftime('%Y/%m/%d'),
                        'provider': 'SecurityTrials'
                    }
                        col.insert_one(securitydata)
                        status = json.loads(open("setting.json","r").read())
                        if str(status['sendmessage']['status']) == "enable":
                            subsendmessage(securitydomain, securitysub, 'SecurityTrials', 'Subdomain')
                            tsubsendmessage(securitydomain, securitysub, 'SecurityTrials', 'Subdomain')
                break
            except:
                if apilen < len(apikey['securitytrails'])-1:
                    apilen += 1
                    # continue
                else:
                    other_webhook.send("SecuriTytrials All Tokens Expire!!!\nPlease Change it...")
                    return
    if len(securitysublist) > 0:
        if str(status['new_sub_nuclei']['status']) == "enable":
            nuclei(securitysublist)

def static_resolve():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    staticsublist = []
    for staticdomain in targets:
        if staticdomain == "":
            continue
        db = mongo[str(staticdomain).replace(".", "-")]
        res = subprocess.getoutput(f"shuffledns -d {staticdomain} -w wordlist/static.txt -r ~/.resolvers -silent")
        res = res.strip()
        
        col = db["resolve"]
        for staticsub in res.split("\n"):
            if str(staticsub) in targets[staticdomain]['out_of_scope']:
                continue
            exist = col.find_one({"subdomain": staticsub})
            if str(exist) == "None":
                staticsublist.append(staticsub)
                staticdata = {
                'subdomain': staticsub,
                'date': td.today().strftime('%Y/%m/%d'),
                'resolver': 'Static_Brute'
            }
                col.insert_one(staticdata)
                status = json.loads(open("setting.json","r").read())
                if str(status['sendmessage']['status']) == "enable":
                    subressendmessage(staticdomain, staticsub, 'Static Resolve', 'Resolve')
                    tsubressendmessage(staticdomain, staticsub, 'Static Resolve', 'Resolve')
    if len(staticsublist) > 0:
        if str(status['new_sub_nuclei']['status']) == "enable":
            nuclei(staticsublist)

def all_resolve():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    resolvesublist = []
    for resolvedomain in targets:
        if resolvedomain == "":
            continue
        db = mongo[str(resolvedomain).replace(".", "-")]
        col = db["all"]
        records = col.find()
        f = open(f"files/{resolvedomain}-all-subs.txt", "a", encoding='utf-8')
        for record in records:
            f.write(record['subdomain']+"\n")
        f.close()
        res = subprocess.getoutput(f"shuffledns -d {resolvedomain} -l files/{resolvedomain}-all-subs.txt -r ~/.resolvers -silent")
        res = res.strip()
        
        col = db["resolve"]
        for resolvesub in res.split("\n"):
            if str(resolvesub) in targets[resolvedomain]['out_of_scope']:
                continue
            exist = col.find_one({"subdomain": resolvesub})
            if str(exist) == "None":
                resolvesublist.append(resolvesub)
                resolvedata = {
                'subdomain': resolvesub,
                'date': td.today().strftime('%Y/%m/%d'),
                'resolver': 'Normal_Subdomain'
            }
                col.insert_one(resolvedata)
                status = json.loads(open("setting.json","r").read())
                if str(status['sendmessage']['status']) == "enable":
                    subressendmessage(resolvedomain, resolvesub, 'Resolve', 'Resolve')
                    tsubressendmessage(resolvedomain, resolvesub, 'Resolve', 'Resolve')
        os.system(f"rm -rf files/{resolvedomain}-all-subs.txt")
    if len(resolvesublist) > 0:
        if str(status['new_sub_nuclei']['status']) == "enable":
            nuclei(resolvesublist)

def dynamic_resolve():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    dynamicsublist = []
    for dynamicdomain in targets:
        if dynamicdomain == "":
            continue
        db = mongo[str(dynamicdomain).replace(".", "-")]
        col = db["all"]
        records = col.find()
        f = open(f"{dynamicdomain}-all-subs.txt", "a", encoding='utf-8')
        for record in records:
            f.write(record['subdomain']+"\n")
        f.close()
        col = db["resolve"]
        
        dnsget = subprocess.getoutput(f"cat {dynamicdomain}-all-subs.txt | dnsgen -w wordlist/gen_alt.txt - | shuffledns -d {dynamicdomain} -r ~/.resolvers -silent")
        for sub in dnsget.split("\n"):
            if str(sub) in targets[dynamicdomain]['out_of_scope']:
                continue
            exist = col.find_one({"subdomain": sub})
            if str(exist) == "None":
                dynamicsublist.append(sub)
                dynamicdata = {
                'subdomain': sub,
                'date': td.today().strftime('%Y/%m/%d'),
                'resolver': 'DNSGen_Resolve'
            }
                col.insert_one(dynamicdata)
                status = json.loads(open("setting.json","r").read())
                if str(status['sendmessage']['status']) == "enable":
                    subressendmessage(dynamicdomain, sub, 'DNSGen_Resolve', 'Resolve')
                    tsubressendmessage(dynamicdomain, sub, 'DNSGen_Resolve', 'Resolve')

    altdns = subprocess.getoutput(f"altdns -i {dynamicdomain}-all-subs.txt -o {dynamicdomain}-altdns.txt -w wordlist/gen_alt.txt && shuffledns -d {dynamicdomain} -l {dynamicdomain}-altdns.txt -r ~/.resolvers -silent")
    
    for sub in altdns.split("\n"):
        exist = col.find_one({"subdomain": sub})
        if str(exist) == "None":
            dynamicsublist.append(sub)
            dynamicdata = {
            'subdomain': sub,
            'date': td.today().strftime('%Y/%m/%d'),
            'resolver': 'ALTDNS_Resolve'
        }
            col.insert_one(dynamicdata)
            status = json.loads(open("setting.json","r").read())
            if str(status['sendmessage']['status']) == "enable":
                subressendmessage(dynamicdomain, sub, 'DNSGen_Resolve', 'Resolve')
                tsubressendmessage(dynamicdomain, sub, 'DNSGen_Resolve', 'Resolve')
    alterx = subprocess.getoutput(f"cat {dynamicdomain}-all-subs.txt | alterx -silent | shuffledns -d {dynamicdomain} -r ~/.resolvers -silent")
    
    for sub in alterx.split("\n"):
        exist = col.find_one({"subdomain": sub})
        if str(exist) == "None":
            dynamicsublist.append()
            dynamicdata = {
            'subdomain': sub,
            'date': td.today().strftime('%Y/%m/%d'),
            'resolver': 'Alterx_Resolve'
        }
            col.insert_one(dynamicdata)
            status = json.loads(open("setting.json","r").read())
            if str(status['sendmessage']['status']) == "enable":
                subressendmessage(dynamicdomain, sub, 'DNSGen_Resolve', 'Resolve')
                tsubressendmessage(dynamicdomain, sub, 'DNSGen_Resolve', 'Resolve')
    os.system(f'rm -rf {dynamicdomain}-all-subs.txt {dynamicdomain}-altdns.txt')
    if len(dynamicsublist) > 0:
        if str(status['new_sub_nuclei']['status']) == "enable":
            nuclei(dynamicsublist)

def httpx():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("targets.json", "r").read())
    today = time.time()
    for httpxdomain in targets:
        if httpxdomain == "":
            continue
        db = mongo[str(httpxdomain).replace(".", "-")]
        col = db["resolve"]
        records = col.find()
        fi = open(f"files/{httpxdomain}-{today}.txt","a")
        for i in records:
            fi.write(i['subdomain']+"\n")
        fi.close()
        httpx = subprocess.getoutput(f"cat files/{httpxdomain}-{today}.txt | httpx -silent -follow-host-redirects -title -status-code -cdn -tech-detect -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0' -H 'Referer: https://$1' -hash md5 > files/{httpxdomain}-{today}-httpx.txt")
        col = db["httpx"]
        new = []
        status = json.loads(open("setting.json","r").read())
        records = open(f"files/{httpxdomain}-{today}-httpx.txt","r").read().split("\n")
        for record in records:
            if record == "":
                continue
            try:
                httpx_details = json.loads(record)
            except:
                continue
            record = httpx_details['input']
            exist = col.find_one({"subdomain": record})
            if str(exist) != "None":
                status_code = exist['status_code']
                title = exist['title']
                tech = exist['tech']
                bodymd5 = exist['bodymd5']
                httpx_status_code = httpx_details['status_code']
                try:
                    httpx_title = httpx_details['title']
                    if httpx_title == "":
                        httpx_title = "Unknown"
                except:
                    httpx_title = "Unknown"
                try:
                    httpx_tech = "".join(httpx_details['tech'][0:-1])
                    if httpx_tech == "":
                        httpx_tech = "Unknown"
                except:
                    httpx_tech = "Unknown"
                httpx_bodymd5 = httpx_details['hash']['body_md5']
                action = ""
                if str(status_code) != str(httpx_status_code):
                    action += action+"Status Code "
                    query = {"subdomain": record}
                    new_values = {"$set": {"status_code": httpx_status_code}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)
                    status = json.loads(open("setting.json","r").read())
                    if str(status['sendmessage']['status']) == "enable" and str(status['change_statuscode']['status']) == "enable":
                        httpxsendmessage(record, status_code,httpx_status_code, "Status Code")
                        thttpxsendmessage(record, status_code,httpx_status_code, "Status Code")

                if str(title) != str(httpx_title):
                    action += action+"Title "
                    query = {"subdomain": record}
                    new_values = {"$set": {"title": httpx_title}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)
                    status = json.loads(open("setting.json","r").read())
                    if str(status['sendmessage']['status']) == "enable" and str(status['change_title']['status']) == "enable":
                        httpxsendmessage(record, title, httpx_title, "Title")
                        thttpxsendmessage(record, title, httpx_title, "Title")

                if str(tech) != str(httpx_tech):
                    action += action+"Tech "
                    query = {"subdomain": record}
                    new_values = {"$set": {"tech": httpx_tech}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)
                    status = json.loads(open("setting.json","r").read())
                    if str(status['sendmessage']['status']) == "enable" and str(status['change_tech']['status']) == "enable":
                        httpxsendmessage(record, tech, httpx_tech, "Tech")
                        thttpxsendmessage(record, tech, httpx_tech, "Tech")

                if str(bodymd5) != str(httpx_bodymd5):
                    action += action+"Body "
                    query = {"subdomain": record}
                    new_values = {"$set": {"bodymd5": httpx_bodymd5}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)
                    status = json.loads(open("setting.json","r").read())
                    if str(status['sendmessage']['status']) == "enable" and str(status['change_body']['status']) == "enable":
                        httpxsendmessage(record, bodymd5, httpx_bodymd5, "Body")
                        thttpxsendmessage(record, bodymd5, httpx_bodymd5, "Body")
            else:
                new.append(record)
                status_code = httpx_details['status_code']
                try:
                    title = httpx_details['title']
                    if title == "":
                        title = "Unknown"
                except:
                    title = "Unknown"
                try:
                    tech = "".join(httpx_details['tech'][0:-1])
                    if tech == "":
                        tech = "Unknown"
                except:
                    tech = "Unknown"
                bodymd5 = httpx_details['hash']['body_md5']
                data = {
                    "subdomain": record,
                    "status_code": status_code,
                    "title": title,
                    "tech": tech,
                    "bodymd5": bodymd5,
                    "last_change": td.today().strftime('%Y/%m/%d'),
                    "action": "New Service"
                }
                col.insert_one(data)
                if str(status['sendmessage']['status']) == "enable":
                    msg = f"========== ***New HTTP Service {record}*** ===========\n"
                    msg += ">>> Subdomain : "
                    msg += f"""```arm
{record}```"""
                    msg += "Status Code : "
                    msg += f"""```arm
{status_code}```"""
                    msg += "Title : "
                    msg += f"""```arm
{title}```"""
                    msg += "Tech : "
                    msg += f"""```arm
{tech}```"""
                    msg += "Date : "
                    msg += f"""```arm
{str(date.today())}```"""
                    new_http_webhook.send(msg)
                    requests.get(f"https://api.telegram.org/bot{new_http_telegram}/sendMessage?chat_id={telegram_chat_id}&text={msg}&parse_mode=MarkDown")
        rm = subprocess.getoutput(f"rm -rf files/{httpxdomain}-{today}-httpx.txt files/{httpxdomain}-{today}.txt")
        if len(new) > 0:
            nuclei(new)
    subprocess.getoutput("rm -rf data/* && mongodump --out data")

def new_template():
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    git = subprocess.getoutput("git clone https://github.com/projectdiscovery/nuclei-templates.git")
    mylist = subprocess.getoutput("find last-nuclei/http/ -type f -name '*.yaml' -o -name '*.yml' | sed 's/last-nuclei/nuclei-templates/g' > files/mytemplate.txt")
    lastlist = subprocess.getoutput("find nuclei-templates/http/ -type f -name '*.yaml' -o -name '*.yml' > files/newtemplate.txt")
    new = subprocess.getoutput("grep -v -f files/mytemplate.txt files/newtemplate.txt")
    newtemplates = str(new).replace("\n", ",")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    if newtemplates != "":
        databases = mongo.list_database_names()
        for database in databases:
            if database in nodatabase:
                continue
            db = mongo[database]
            col = db["resolve"]
            all = col.find()
            f = open(f"files/{database}_subs.txt", "a")
            for templatesub in all:
                templatesub = templatesub['subdomain']
                f.write(templatesub+"\n")
            f.close()
        allsubsfile = subprocess.getoutput("ls files/").split()
        for file in allsubsfile:
            try:
                check = file.split("_")[0]
            except:
                continue
            if str(check) in databases:
                # nuclei = subprocess.getoutput(f"nuclei -l files/{file} -t {newtemplates} -o output/{check}_{str(td.today().strftime('%Y/%m/%d'))}.txt -silent | notify -silent")
                nuclei = subprocess.getoutput(f"nuclei -l files/{file} -t {newtemplates} -o output/{check}_{str(td.today().strftime('%Y/%m/%d'))}.txt -silent")
                for i in nuclei.split("\n"):
                    nuclei_webhook.send(f"```{i}```")
                    requests.get(f"https://api.telegram.org/bot{nuclei_telegram}/sendMessage?chat_id={telegram_chat_id}&text=```{i}```&parse_mode=MarkDown")
        msg = f"========== ***New Nuclei Templates*** ===========\n"
        for i in newtemplates.split("\n"):
            msg += f"`{i}`"
        nuclei_webhook.send(msg)
        requests.get(f"https://api.telegram.org/bot{nuclei_telegram}/sendMessage?chat_id={telegram_chat_id}&text={msg}&parse_mode=MarkDown")
        # subprocess.getoutput(f"echo '{New Nuclei Templates : \n{newtemplates}}' | notify -silent")
    mv = subprocess.getoutput("rm -rf last-nuclei && mv nuclei-templates last-nuclei")
    remove_files = subprocess.getoutput("rm -rf files/*")
    
def nuclei(list):   
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    file = open("newsubs.txt","a")
    time = str(datetime.datetime.now()).replace(" ","_")
    for nsub in list:
        file.write(nsub+"\n")
    file.close()
    status = json.loads(open("setting.json","r").read())
    nuclei_update = subprocess.getoutput("nuclei -update -update-templates")
    # nuclei = subprocess.getoutput(f"nuclei -l newsubs.txt {str(status['nuclei_command']['command'])} -o output/{time}.txt | notify -silent")
    nuclei = subprocess.getoutput(f"nuclei -l newsubs.txt {str(status['nuclei_command']['command'])} -o output/{time}.txt")
    for i in nuclei.split("\n"):
        nuclei_webhook.send(f"```{i}```")
        requests.get(f"https://api.telegram.org/bot{nuclei_telegram}/sendMessage?chat_id={telegram_chat_id}&text=```{i}```&parse_mode=MarkDown")
    rm = subprocess.getoutput("rm -rf newsubs.txt")

while True:
    try:
        lastfile = open("setting.json","r").read()
        setting = json.loads(lastfile)
        h = open("setting.json","rb").read()
        hash = hashlib.md5(h).hexdigest()
        subfinder_setting = setting['subfinder']
        crt_setting = setting['crt']
        securitytrials_setting = setting['securitytrials']
        static_resolve_setting = setting['static_resolve']
        all_resolve_setting = setting['all_resolve']
        dynamic_resolve_setting = setting['dynamic_resolve']
        httpx_setting = setting['httpx']
        new_template_setting = setting['new_template']

        if subfinder_setting['status'] == "enable":
            subfinder_job = schedule.every(int(subfinder_setting['value'])).__getattribute__(subfinder_setting['time']).do(subfinder)
        else:
            try:
                schedule.cancel_job(subfinder_job)
            except:
                pass
        
        if crt_setting['status'] == "enable":
            crt_job = schedule.every(int(crt_setting['value'])).__getattribute__(crt_setting['time']).do(crt)
        else:
            try:
                schedule.cancel_job(crt_job)
            except:
                pass
        
        if securitytrials_setting['status'] == "enable":
            securitytrials_job = schedule.every(int(securitytrials_setting['value'])).__getattribute__(securitytrials_setting['time']).do(securitytrials)
        else:
            try:
                schedule.cancel_job(securitytrials_job)
            except:
                pass
        
        if static_resolve_setting['status'] == "enable":
            static_resolve_job = schedule.every(int(static_resolve_setting['value'])).__getattribute__(static_resolve_setting['time']).do(static_resolve)
        else:
            try:
                schedule.cancel_job(static_resolve_job)
            except:
                pass
        
        if all_resolve_setting['status'] == "enable":
            all_resolve_job = schedule.every(int(all_resolve_setting['value'])).__getattribute__(all_resolve_setting['time']).do(all_resolve)
        else:
            try:
                schedule.cancel_job(all_resolve_job)
            except:
                pass
        
        if dynamic_resolve_setting['status'] == "enable":
            dynamic_resolve_job = schedule.every(int(dynamic_resolve_setting['value'])).__getattribute__(dynamic_resolve_setting['time']).do(dynamic_resolve)
        else:
            try:
                schedule.cancel_job(dynamic_resolve_job)
            except:
                pass
        
        if httpx_setting['status'] == "enable":
            httpx_job = schedule.every(int(httpx_setting['value'])).__getattribute__(httpx_setting['time']).do(httpx)
        else:
            try:
                schedule.cancel_job(httpx_job)
            except:
                pass
        
        if new_template_setting['status'] == "enable":
            new_template_job = schedule.every(int(new_template_setting['value'])).__getattribute__(new_template_setting['time']).do(new_template)
        else:
            try:
                schedule.cancel_job(new_template_job)
            except:
                pass
        while True:
            newhash = hashlib.md5(open("setting.json","rb").read()).hexdigest()
            if str(newhash) == hash:
                schedule.run_pending()
                time.sleep(10)
            else:
                break
    except Exception:
        er = traceback.format_exc()
        print(er)
        other_webhook.send("Tower Stoped\nCheck it")
        requests.get(f"https://api.telegram.org/bot{other_telegram}/sendMessage?chat_id={telegram_chat_id}&text=Tower+Stoped%0a%0a{er}")
        subprocess.getoutput("sudo systemctl unmask mongod")
        subprocess.getoutput("sudo service mongod start")
        # time.sleep(60)
        # other_webhook.send(traceback.format_exc())
