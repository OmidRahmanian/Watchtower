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
other_webhook = SyncWebhook.from_url(os.environ["OTHER_WEBHOOK_URL"])
mongo = pymongo.MongoClient("mongodb://localhost:27017/")


def subfinder():
    targets = json.loads(open("starttargets.json", "r").read())
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

def crt():
    targets = json.loads(open("starttargets.json", "r").read())
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

def securitytrials():
    # TODO: Add comma-separated SecurityTrails API keys to this environment variable.
    securitytrails_keys = [key.strip() for key in os.environ.get("SECURITYTRAILS_API_KEYS", "").split(",") if key.strip()]
    if not securitytrails_keys:
        raise RuntimeError("SECURITYTRAILS_API_KEYS is not configured")
    apikey = {"securitytrails": securitytrails_keys}
    mongo = pymongo.MongoClient("mongodb://localhost:27017/")
    targets = json.loads(open("starttargets.json", "r").read())
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
            response = requests.get(url, headers=headers)
            js = json.loads(response.text)
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
                break
            except:
                if apilen < len(apikey['securitytrails'])-1:
                    apilen += 1
                    # continue
                else:
                    other_webhook.send("SecuriTytrials All Tokens Expire!!!\nPlease Change it...")
                    return

def static_resolve():
    targets = json.loads(open("starttargets.json", "r").read())
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

def all_resolve():
    targets = json.loads(open("starttargets.json", "r").read())
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
        os.system(f"rm -rf files/{resolvedomain}-all-subs.txt")

def httpx():
    targets = json.loads(open("starttargets.json", "r").read())
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
        httpx = subprocess.getoutput(f"cat files/{httpxdomain}-{today}.txt | httpx -silent -follow-host-redirects -title -status-code -cdn -tech-detect -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0' -H 'Referer: https://$1' -json > files/{httpxdomain}-{today}-httpx.txt")
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

                if str(title) != str(httpx_title):
                    action += action+"Title "
                    query = {"subdomain": record}
                    new_values = {"$set": {"title": httpx_title}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)

                if str(tech) != str(httpx_tech):
                    action += action+"Tech "
                    query = {"subdomain": record}
                    new_values = {"$set": {"tech": httpx_tech}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)

                if str(bodymd5) != str(httpx_bodymd5):
                    action += action+"Body "
                    query = {"subdomain": record}
                    new_values = {"$set": {"bodymd5": httpx_bodymd5}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"last_change": td.today().strftime('%Y/%m/%d')}}
                    col.update_one(query, new_values)
                    new_values = {"$set": {"action": action}}
                    col.update_one(query, new_values)
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
        rm = subprocess.getoutput(f"rm -rf files/{httpxdomain}-{today}-httpx.txt files/{httpxdomain}-{today}.txt")

try:
    subfinder()
    crt()
    securitytrials()
    all_resolve()
    static_resolve()
    httpx()
    targets = json.loads(open("starttargets.json", "r").read())

    with open('targets.json', 'r') as f:
        data = json.load(f)
    for i in targets:
        new_data = {
            i: {
                "report_url": targets[i]['report_url'],
                "out_of_scope": targets[i]['out_of_scope']
            }
        }
        data.update(new_data)


    with open('targets.json', 'w') as f:
        json.dump(data, f)
    f.close()

    other_webhook.send("Start Tower End")
except Exception:
    print(traceback.format_exc())
    other_webhook.send("Tower Stoped\nCheck it")
    other_webhook.send(traceback.format_exc())
