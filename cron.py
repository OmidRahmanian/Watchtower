import schedule
import time
import json
import hashlib

# setting = json.loads(open("setting.json","r").read())
def read():
    setting = json.loads(open("setting.json","r").read())
    return setting
# subfinder_setting = setting['subfinder']
def print_second():
    print("second : "+time.strftime("%S"))

def print_minute():
    print("minute : "+time.strftime("%M"))

# if subfinder_setting['status'] == "enable":
#     schedule.every(int(subfinder_setting['value'])).__getattribute__(subfinder_setting['time']).do(print_second)


while True:
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
       subfinder_job = schedule.every(int(subfinder_setting['value'])).__getattribute__(subfinder_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if crt_setting['status'] == "enable":
       crt_job = schedule.every(int(crt_setting['value'])).__getattribute__(crt_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if securitytrials_setting['status'] == "enable":
       securitytrials_job = schedule.every(int(securitytrials_setting['value'])).__getattribute__(securitytrials_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if static_resolve_setting['status'] == "enable":
       static_resolve_job = schedule.every(int(static_resolve_setting['value'])).__getattribute__(static_resolve_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if all_resolve_setting['status'] == "enable":
       all_resolve_job = schedule.every(int(all_resolve_setting['value'])).__getattribute__(all_resolve_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if dynamic_resolve_setting['status'] == "enable":
       dynamic_resolve_job = schedule.every(int(dynamic_resolve_setting['value'])).__getattribute__(dynamic_resolve_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if httpx_setting['status'] == "enable":
       subfinder_job = schedule.every(int(httpx_setting['value'])).__getattribute__(httpx_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    
    if new_template_setting['status'] == "enable":
       new_template_job = schedule.every(int(new_template_setting['value'])).__getattribute__(new_template_setting['time']).do(print_second)
    else:
        schedule.cancel_job(subfinder_job)
    while True:
        newhash = hashlib.md5(open("setting.json","rb").read()).hexdigest()
        if str(newhash) == hash:
            schedule.run_pending()
            time.sleep(10)
        else:
            break
