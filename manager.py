import pymongo
from colorama import Fore,init
import time
from pprint import pprint
from rich import print_json 
import json
from datetime import datetime,date
import sys

mongo = pymongo.MongoClient("mongodb://localhost:27017/")

init()
def banner():
    print(f"""
{Fore.CYAN}  _                         {Fore.WHITE}                                              
{Fore.CYAN} | |                        {Fore.WHITE}                                              
{Fore.CYAN} | |_ _____      _____ _ __ {Fore.WHITE}  _ __ ___   __ _ _ __   __ _  __ _  ___ _ __ 
{Fore.CYAN} | __/ _ \ \ /\ / / _ \ '__|{Fore.WHITE} | '_ ` _ \ / _` | '_ \ / _` |/ _` |/ _ \ '__|
{Fore.CYAN} | || (_) \ V  V /  __/ |   {Fore.WHITE} | | | | | | (_| | | | | (_| | (_| |  __/ |   
{Fore.CYAN}  \__\___/ \_/\_/ \___|_|   {Fore.WHITE} |_| |_| |_|\__,_|_| |_|\__,_|\__, |\___|_|   
{Fore.CYAN}                            {Fore.WHITE}                               __/ |          
{Fore.CYAN}                            {Fore.WHITE}                              |___/           
""")

def getall():
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    t = str(time.time()).split(".")[0]
    databases = mongo.list_database_names()
    c = 1
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    if int(inp) > len(l):
        for i in l:
            db = mongo[i]
            col = db['all']
            records = col.find()
            for subs in records:
                if str(subs) != "None":
                    f = open(f"export/{i}-{t}.txt","a")
                    f.write(subs['subdomain']+"\n")
            try:
                f.close()
            except:
                pass
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    else:
        db = mongo[l[int(inp)-1]]
        col = db['all']
        records = col.find()
        for subs in records:
            if str(subs) != "None":
                f = open(f"export/{l[int(inp)-1]}-{t}.txt","a")
                f.write(subs['subdomain']+"\n")
        try:
            f.close()
        except:
            pass
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    menu()

def singledomain():
    subdomain = input(Fore.WHITE+f"Enter Your Subdomain Name: {Fore.WHITE} >>> ")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    databases = mongo.list_database_names()
    for database in databases:
        if database in nodatabase:
            continue
        db = mongo[database]
        for colaction in db.list_collection_names():
            col = db[colaction]
            records = col.find({"subdomain":subdomain})
            for record in records:
                if str(record) != "None":
                    record = str(record).replace("ObjectId('","'").replace("')","'")
                    record = record.replace("'",'"')
                    record = record.replace("'",'')
                    record = json.loads(record)
                    print("\n")
                    print(f"{Fore.CYAN}Database : {Fore.WHITE}{database}")
                    print(f"{Fore.CYAN}Colaction : {Fore.WHITE}{colaction}")
                    print_json(data=record)
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def lastsub():
    def days_between(d1, d2):
        d1 = datetime.strptime(d1, '%Y/%m/%d')
        d2 = datetime.strptime(d2, '%Y/%m/%d')
        return abs((d2 - d1).days)
    
    today = date.today()
    today = today.strftime("%Y/%m/%d")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    t = str(time.time()).split(".")[0]
    databases = mongo.list_database_names()
    c = 1
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    day = input(Fore.WHITE+f"A few days ago? {Fore.CYAN}>>> {Fore.WHITE}")
    if int(inp) > len(l):
        for i in l:
            c = 0
            db = mongo[i]
            col = db['all']
            records = col.find()
            for subs in records:
                dif = days_between(subs['date'],today)
                if int(dif) <= int(day):
                    c += 1
                    f = open(f"export/{i}-{str(day)}day.txt","a")
                    f.write(subs['subdomain']+"\n")
            try:
                f.close()
            except:
                pass
            print(f"{Fore.CYAN}{i} : {Fore.WHITE}{c} Line")
        print(f"{Fore.GREEN}\nSuccessful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    else:
        c = 0
        db = mongo[l[int(inp)-1]]
        col = db['all']
        records = col.find()
        for subs in records:
            dif = days_between(subs['date'],today)
            if int(dif) <= int(day):
                c += 1
                f = open(f"export/{l[int(inp)-1]}-{str(day)}day.txt","a")
                f.write(subs['subdomain']+"\n")
        try:
            f.close()
        except:
            pass
        print(f"{Fore.CYAN}{l[int(inp)-1]} : {Fore.WHITE}{c} Line")
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    menu()

def getallhttp():
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    t = str(time.time()).split(".")[0]
    databases = mongo.list_database_names()
    c = 1
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    if int(inp) > len(l):
        for i in l:
            db = mongo[i]
            col = db['httpx']
            records = col.find()
            for subs in records:
                if str(subs) != "None":
                    f = open(f"export/{i}-{t}.txt","a")
                    f.write(f"{subs['subdomain']} [{str(subs['status_code'])}] [{str(subs['title'])}] [{str(subs['tech'])}]\n")
            try:
                f.close()
            except:
                pass
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    else:
        db = mongo[l[int(inp)-1]]
        col = db['httpx']
        records = col.find()
        for subs in records:
            if str(subs) != "None":
                f = open(f"export/{l[int(inp)-1]}-{t}.txt","a")
                f.write(f"{subs['subdomain']} [{str(subs['status_code'])}] [{str(subs['title'])}] [{str(subs['tech'])}]\n")
        try:
            f.close()
        except:
            pass
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    menu()

def lastresolvesub():
    def days_between(d1, d2):
        d1 = datetime.strptime(d1, '%Y/%m/%d')
        d2 = datetime.strptime(d2, '%Y/%m/%d')
        return abs((d2 - d1).days)
    
    today = date.today()
    today = today.strftime("%Y/%m/%d")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    t = str(time.time()).split(".")[0]
    databases = mongo.list_database_names()
    c = 1
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    day = input(Fore.WHITE+f"A few days ago? {Fore.CYAN}>>> {Fore.WHITE}")
    if int(inp) > len(l):
        for i in l:
            c = 0
            db = mongo[i]
            col = db['resolve']
            records = col.find()
            for subs in records:
                dif = days_between(subs['date'],today)
                if int(dif) <= int(day):
                    c += 1
                    f = open(f"export/{i}-{str(day)}day.txt","a")
                    f.write(subs['subdomain']+"\n")
            try:
                f.close()
            except:
                pass
            print(f"{Fore.CYAN}{i} : {Fore.WHITE}{c} Line")
        print(f"{Fore.GREEN}\nSuccessful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    else:
        c = 0
        db = mongo[l[int(inp)-1]]
        col = db['resolve']
        records = col.find()
        for subs in records:
            dif = days_between(subs['date'],today)
            if int(dif) <= int(day):
                c += 1
                f = open(f"export/{l[int(inp)-1]}-{str(day)}day.txt","a")
                f.write(subs['subdomain']+"\n")
        try:
            f.close()
        except:
            pass
        print(f"{Fore.CYAN}{l[int(inp)-1]} : {Fore.WHITE}{c} Line")
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    menu()

def lasthttpesub():
    def days_between(d1, d2):
        d1 = datetime.strptime(d1, '%Y/%m/%d')
        d2 = datetime.strptime(d2, '%Y/%m/%d')
        return abs((d2 - d1).days)
    
    today = date.today()
    today = today.strftime("%Y/%m/%d")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    t = str(time.time()).split(".")[0]
    databases = mongo.list_database_names()
    c = 1
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    day = input(Fore.WHITE+f"A few days ago? {Fore.CYAN}>>> {Fore.WHITE}")
    if int(inp) > len(l):
        for i in l:
            c = 0
            db = mongo[i]
            col = db['httpx']
            records = col.find()
            for subs in records:
                dif = days_between(subs['last_change'],today)
                if int(dif) <= int(day):
                    c += 1
                    f = open(f"export/{i}-{str(day)}day.txt","a")
                    f.write(subs['subdomain']+"\n")
            try:
                f.close()
            except:
                pass
            print(f"{Fore.CYAN}{i} : {Fore.WHITE}{c} Line")
        print(f"{Fore.GREEN}\nSuccessful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    else:
        c = 0
        db = mongo[l[int(inp)-1]]
        col = db['httpx']
        records = col.find()
        for subs in records:
            dif = days_between(subs['last_change'],today)
            if int(dif) <= int(day):
                c += 1
                f = open(f"export/{l[int(inp)-1]}-{str(day)}day.txt","a")
                f.write(subs['subdomain']+"\n")
        try:
            f.close()
        except:
            pass
        print(f"{Fore.CYAN}{l[int(inp)-1]} : {Fore.WHITE}{c} Line")
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    menu()

def getallresolve():
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    t = str(time.time()).split(".")[0]
    databases = mongo.list_database_names()
    c = 1
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    if int(inp) > len(l):
        for i in l:
            db = mongo[i]
            col = db['resolve']
            records = col.find()
            for subs in records:
                if str(subs) != "None":
                    f = open(f"export/{i}-{t}.txt","a")
                    f.write(subs['subdomain']+"\n")
            try:
                f.close()
            except:
                pass
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    else:
        db = mongo[l[int(inp)-1]]
        col = db['resolve']
        records = col.find()
        for subs in records:
            if str(subs) != "None":
                f = open(f"export/{l[int(inp)-1]}-{t}.txt","a")
                f.write(subs['subdomain']+"\n")
        try:
            f.close()
        except:
            pass
        print(f"{Fore.GREEN}Successful...    Check export Folder\n")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
    menu()    

def query():
    q = input(f"{Fore.CYAN}Enter Your JSON Query {Fore.WHITE} >>> ")
    try:
        t = str(time.time()).split(".")[0]
        qj = json.loads(str(q))
        nodatabase = ['admin', 'config', 'local','programs_watcher']
        databases = mongo.list_database_names()
        for database in databases:
            if database in nodatabase:
                continue
            db = mongo[database]
            colaction = db.list_collection_names()
            for col in colaction:
                col = db[col]
                record = col.find(qj)
                for rec in record:
                    if str(record) != "None":
                        f = open(f"export/{database}-query-{t}.txt","a")
                        rec = str(rec).replace("ObjectId('","'").replace("')","'")
                        rec = rec.replace("'",'"')
                        rec = rec.replace("'",'')
                        rec = json.loads(rec)
                        f.write(str(rec).replace("'",'"'))
                        print("\n")
                        print_json(data=rec)
            try:
                f.close()
            except:
                pass
        input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
        menu()
    except:
        print(Fore.RED+"You JSON Query Not Valid :(")
        input(Fore.WHITE+"Press Any Key To Return Menu ...")
        menu()

def status_search():
    t = str(time.time()).split(".")[0]
    code = input(f"{Fore.CYAN}Enter Your Status Code {Fore.WHITE} >>> ")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    databases = mongo.list_database_names()
    for database in databases:
        db = mongo[database]
        col = db['httpx']
        record = col.find({"status_code" : {"$regex" : code, "$options": "i"}})
        for rec in record:
            if str(record) != "None":
                f = open(f"export/{database}-{code}code-{t}.txt","a")
                rec = str(rec).replace("ObjectId('","'").replace("')","'")
                rec = rec.replace("'",'"')
                rec = rec.replace("'",'')
                rec = json.loads(rec)
                f.write(str(rec).replace("'",'"'))
                print("\n")
                print_json(data=rec)
        try:
            f.close()
        except:
            pass
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def tech_search():
    t = str(time.time()).split(".")[0]
    tech = input(f"{Fore.CYAN}Enter Your Tech {Fore.WHITE} >>> ")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    databases = mongo.list_database_names()
    for database in databases:
        db = mongo[database]
        col = db['httpx']
        record = col.find({"tech" : {"$regex" : tech, "$options": "i"}})
        for rec in record:
            if str(record) != "None":
                f = open(f"export/{database}-{tech}-{t}.txt","a")
                rec = str(rec).replace("ObjectId('","'").replace("')","'")
                rec = rec.replace("'",'"')
                rec = rec.replace("'",'')
                rec = json.loads(rec)
                f.write(str(rec).replace("'",'"'))
                print("\n")
                print_json(data=rec)
        try:
            f.close()
        except:
            pass
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def title_search():
    t = str(time.time()).split(".")[0]
    title = input(f"{Fore.CYAN}Enter Your Title {Fore.WHITE} >>> ")
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    databases = mongo.list_database_names()
    for database in databases:
        db = mongo[database]
        col = db['httpx']
        record = col.find({"title" : {"$regex" : title, "$options": "i"}})
        for rec in record:
            if str(record) != "None":
                f = open(f"export/{database}-{title}-{t}.txt","a")
                rec = str(rec).replace("ObjectId('","'").replace("')","'")
                rec = rec.replace("'",'"')
                rec = rec.replace("'",'')
                rec = json.loads(rec)
                f.write(str(rec).replace("'",'"'))
                print("\n")
                print_json(data=rec)
        try:
            f.close()
        except:
            pass
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def setting():
    setting = json.loads(open("setting.json","r").read())
    c = 1
    l = []
    for i in setting:
        l.append(i)
        f = f"{Fore.WHITE}[{Fore.YELLOW}{c}{Fore.WHITE}] {Fore.YELLOW}{i}{Fore.WHITE} :"
        space = " "*(46-len(f))
        if setting[i]['status'] == "enable":
            color = Fore.GREEN
        else:
            color = Fore.RED
        status_space = " "*(7-len(setting[i]['status']))
        try:
            time_space = " "*(5-len(setting[i]['time']))
        except:
            time_space = ""
        try:
            print(f"{f+space} {Fore.WHITE}Status : {color}{setting[i]['status']+status_space} {Fore.CYAN}| {Fore.WHITE}Time{Fore.CYAN} : {setting[i]['time']+time_space} | {Fore.WHITE}Value{Fore.CYAN} : {setting[i]['value']}")
        except:
            print(f"{f+space} {Fore.WHITE}Status : {color}{setting[i]['status']+status_space}")
        c += 1
    inp = input(Fore.CYAN+">>> ")
    for i in setting:
        if i == l[int(inp)-1]:
            li = []
            c = 1
            print(i)
            for a in setting[i]:
                print(f"{Fore.WHITE}[{Fore.YELLOW}{c}{Fore.WHITE}] {Fore.YELLOW}{a} {Fore.WHITE}: {setting[i][a]}")
                li.append(a)
                c += 1
            change = input(Fore.CYAN+">>> ")
            newvalue = input(f"{Fore.CYAN}Enter Your New {Fore.YELLOW}{li[(int(change)-1)]} {Fore.WHITE}>>> ")
            setting[i][li[(int(change)-1)]] = newvalue
            break
    rec = str(setting[i])
    rec = rec.replace("'",'"')
    rec = rec.replace("'",'')
    rec = json.loads(rec)
    print_json(data=rec)
    confirm = input(f"{Fore.YELLOW}Do you confirm the information?[Y/N] {Fore.WHITE}>>> ")
    if str(confirm).lower() != "n":
        newsetting = open("setting.json","w")
        newsetting.write(str(setting).replace("'",'"'))
        newsetting.close()
        print(Fore.GREEN+"successfull :)")
        input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def addtarget():
    targetdomain = input(f"{Fore.CYAN}Enter Your New Target {Fore.WHITE} >>> ")
    reportpage = input(f"{Fore.CYAN}Enter Target Report Page URL {Fore.WHITE} >>> ")
    out_of_scope = input(f"{Fore.CYAN}Enter Target Out Of Scopes (Split With ',') {Fore.WHITE} >>> ")
    with open('targets.json', 'r') as f:
        data = json.load(f)
    new_data = {
        targetdomain: {
            "report_url": reportpage,
            "out_of_scope": out_of_scope.split(",")
        }
    }
    data.update(new_data)
    with open('targets.json', 'w') as f:
        json.dump(data, f)
    print(f"{Fore.GREEN}Target Added :)")
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def deltarget():
    with open('targets.json', 'r') as f:
        data = json.load(f)
    l = []
    c = 1
    for i in data:
        l.append(i)
        print(f"{Fore.CYAN}[{Fore.WHITE}{str(c)}{Fore.CYAN}] : {Fore.WHITE}{i}")
        c += 1
    d = input(f"{Fore.CYAN}>>> ")
    for i in d.split(","):
        del data[l[int(i)-1]]
    with open('targets.json', 'w') as f:
        json.dump(data, f)
    print(f"{Fore.RED}Target Deleted :)")
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def edittarget():
    with open('targets.json', 'r') as f:
        data = json.load(f)
    l = []
    c = 1
    for i in data:
        l.append(i)
        print(f"{Fore.CYAN}[{Fore.WHITE}{str(c)}{Fore.CYAN}] : {Fore.WHITE}{i}")
        c += 1
    d = input(f"{Fore.CYAN}>>> ")
    print(f"{Fore.CYAN}{l[int(d)-1]} {Fore.WHITE}:")
    print(f"{Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}]{Fore.YELLOW}URL {Fore.WHITE}: {Fore.CYAN}{data[l[int(d)-1]]['report_url']}")
    print(f"{Fore.CYAN}[{Fore.WHITE}2{Fore.CYAN}]{Fore.YELLOW}Out Of Scopes {Fore.WHITE}: {Fore.CYAN}{data[l[int(d)-1]]['out_of_scope']}")
    index = input(f"{Fore.CYAN}Enter Your Index {Fore.WHITE} >>> ")
    if index == "1":
        new_url = input(f"{Fore.CYAN}Enter New Report URL {Fore.WHITE} >>> ")
        data[l[int(d)-1]]['report_url'] = new_url
    elif  index == "2":
        new_out_of_scope = input(f"{Fore.CYAN}Enter New Out Of Scopes (Split With ',') {Fore.WHITE} >>> ")
        data[l[int(d)-1]]['out_of_scope'] = new_out_of_scope.split(",")
    with open('targets.json', 'w') as f:
        json.dump(data, f)
    print(f"{Fore.YELLOW}Target Updated :)")
    with open('targets.json', 'r') as f:
        data = json.load(f)
    print_json(data=data[l[int(d)-1]])
    input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()

def delldatabase():
    nodatabase = ['admin', 'config', 'local','programs_watcher']
    databases = mongo.list_database_names()
    c = 0
    l = []
    for database in databases:
        if database in nodatabase:
            continue
        print(f"{Fore.CYAN}[{Fore.WHITE}{c}{Fore.CYAN}] {Fore.WHITE}{database}")
        c += 1
        l.append(database)
    print(f"{Fore.YELLOW}[{Fore.WHITE}{c}{Fore.YELLOW}] {Fore.WHITE}All")
    inp = input(Fore.CYAN+f">>> {Fore.WHITE}")
    print(c)
    if str(inp) == str(c):
        confirm = input(f"{Fore.RED}Are you sure you want to delete {Fore.YELLOW}All{Fore.RED} database? {Fore.YELLOW}[Y/N]{Fore.WHITE} >>> ")
        if confirm == "y" or confirm == "Y":
            for database in databases:
                if database in nodatabase:
                    continue
                mongo.drop_database(database)
            print(f"{Fore.WHITE}All {Fore.GREEN}Delete Successfull :)")
            input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
        else:
            print(f"{Fore.RED}Delete Database Canceled !!!")
            input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    else:
        confirm = input(f"{Fore.RED}Are you sure you want to delete the {Fore.YELLOW}{l[int(inp)]}{Fore.RED} database? {Fore.YELLOW}[Y/N]{Fore.WHITE} >>> ")
        if confirm == "y" or confirm == "Y":
            mongo.drop_database(l[int(inp)])
            print(f"{Fore.WHITE}{l[int(inp)]} {Fore.GREEN}Delete Successfull :)")
            input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
        else:
            print(f"{Fore.RED}Delete Database Canceled !!!")
        input(Fore.WHITE+"\nPress Any Key To Return Menu ...")
    menu()
    
def menu():
    banner()
    print(f"{Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] {Fore.WHITE}Get All Subdomains")
    print(f"{Fore.CYAN}[{Fore.WHITE}2{Fore.CYAN}] {Fore.WHITE}Get Resolve Subdomains")
    print(f"{Fore.CYAN}[{Fore.WHITE}3{Fore.CYAN}] {Fore.WHITE}Get HTTP Subdomains")
    print(f"{Fore.CYAN}[{Fore.WHITE}4{Fore.CYAN}] {Fore.WHITE}Get Lasts Subdomains")
    print(f"{Fore.CYAN}[{Fore.WHITE}5{Fore.CYAN}] {Fore.WHITE}Get Lasts Resolve Subdomains")
    print(f"{Fore.CYAN}[{Fore.WHITE}6{Fore.CYAN}] {Fore.WHITE}Get Lasts HTTP Subdomains")
    print(f"{Fore.CYAN}[{Fore.WHITE}7{Fore.CYAN}] {Fore.WHITE}Get Single Subdomain Details")
    print(f"{Fore.CYAN}[{Fore.WHITE}8{Fore.CYAN}] {Fore.WHITE}Set Default Query")
    print(f"{Fore.CYAN}[{Fore.WHITE}9{Fore.CYAN}] {Fore.WHITE}Get Subdomains With Status Code")
    print(f"{Fore.CYAN}[{Fore.WHITE}10{Fore.CYAN}] {Fore.WHITE}Get Subdomains With Tech")
    print(f"{Fore.CYAN}[{Fore.WHITE}11{Fore.CYAN}] {Fore.WHITE}Get Subdomains With Title")
    print(f"{Fore.CYAN}[{Fore.WHITE}12{Fore.CYAN}] {Fore.WHITE}Change Settings")
    print(f"{Fore.CYAN}[{Fore.WHITE}13{Fore.CYAN}] {Fore.WHITE}Add Target")
    print(f"{Fore.CYAN}[{Fore.WHITE}14{Fore.CYAN}] {Fore.WHITE}Delete Target")
    print(f"{Fore.CYAN}[{Fore.WHITE}15{Fore.CYAN}] {Fore.WHITE}Edit Target")
    print(f"{Fore.CYAN}[{Fore.WHITE}16{Fore.CYAN}] {Fore.WHITE}Delete Database")
    inp = input(Fore.CYAN+">>> ")
    if str(inp) == "1":
        getall()
    elif str(inp) == "2":
        getallresolve()
    elif str(inp) == "3":
        getallhttp()
    elif str(inp) == "4":
        lastsub()
    elif str(inp) == "5":
        lastresolvesub()
    elif str(inp) == "6":
        lasthttpesub()
    elif str(inp) == "7":
        singledomain()
    elif str(inp) == "8":
        query()
    elif str(inp) == "9":
        status_search()
    elif str(inp) == "10":
        tech_search()
    elif str(inp) == "11":
        title_search()
    elif str(inp) == "12":
        setting()
    elif str(inp) == "13":
        addtarget()
    elif str(inp) == "14":
        deltarget()
    elif str(inp) == "15":
        edittarget()
    elif str(inp) == "16":
        delldatabase()
    else:
        sys.exit()

menu()