import os
import requests
import argparse
import time
import json 

""" for now a zaproxy process for onetime execution and dies  
    phase 2: will run multiple automation workflow once all done process dies better integration with multiple pipeline in the same host
"""


def main():
    parser = argparse.ArgumentParser(description="OWASP ZAP Automation Script")
    subparsers = parser.add_subparsers(dest="command", title="Commands")
    parser_start = subparsers.add_parser("start", help="Start OWASP ZAP")
    parser_start.add_argument("-forceduser", action="store_true", help="Enable forced user mode")
    parser_start.add_argument("-mode", choices=["attack", "standard"], help="Set mode to attack or standard")
    parser_start.add_argument("-attack", choices=["on", "off"], help="Enable or disable attacks")
    parser_update = subparsers.add_parser("update", help="Update ZAP configuration")
    parser_update.add_argument("-mode", choices=["attack", "standard"], help="Set mode to attack or standard")
    parser_update.add_argument("-attack", choices=["on", "off"], help="Enable or disable attacks")
    parser_run = subparsers.add_parser("run", help="Run ZAP automation")
    parser_run.add_argument("-auto", help="Specify the file path for automation")
    parser_run = subparsers.add_parser("checkzap", help="Check ZAP is running")
    parser_run = subparsers.add_parser("init", help="load all the community script and enable them")
    parser_run = subparsers.add_parser("shut", help="shutdown zap")
    parser_run = subparsers.add_parser("checkauto", help="check automation running status {deprecated}")
    parser_start.add_argument("-id", help="automation id")
    args = parser.parse_args()

    api_key = os.environ.get("ZAP_API_KEY")
    url = "http://localhost:11111"  # Replace with your ZAP URL
    # change zaproxy to zap.sh
    if args.command == "start":
        start_zap(url,api_key)
        if args.attack == "on":
            attack_startup(url,api_key,"true")
        else:
            attack_startup(url,api_key,"false") 
        if args.mode == "attack":
            attack_mode(url,api_key,"attack")
        else:
            attack_mode(url,api_key,"standard")
        if args.forceduser:
            forcedUser(url,api_key)
        else:
            forcedUserdisable(url,api_key)

    elif args.command == "update":
        if args.mode == "attack":
            attack_mode(url,api_key,"attack")
        else:
            attack_mode(url,api_key,"standard")
        if args.attack == "on":
            attack_startup(url,api_key,"true")
        else:
            attack_startup(url,api_key,"false")
    elif args.command == "checkzap":
        check_zap_running(url)
    elif args.command == "run":
        print(args.auto)
        automation(url,api_key,args.auto)
    elif args.command == "init":
        init_zap_script(url,api_key)
    elif args.command == "shut":
        stop_zap(url,api_key)
    elif args.command == "checkauto":
        check_auto(url,api_key,args.id)
    else:
        parser.print_help()



""" zap configuration  """
def init_zap_script(url,api_key):
    script = ["bxss.py","corsair.py","Cross Site WebSocket Hijacking.js","cve-2019-5418.js","gof_lite.js","JWT None Exploit.js","RCE.py","SSTI.js","SSTI.py","TestInsecureHTTPVerbs.py","clacks.js","CookieHTTPOnly.js","detect_csp_notif_and_reportonly.js","detect_samesite_protection.js","find base64 strings.js","Find Hashes.js","Find HTML Comments.js","Find IBANs.js","find_reflected_params.py","google_api_keys_finder.js","HUNT.py","IDOR.py","Mutliple Security Header Check.js","Report non static sites.js","RPO.js","Server Header Disclosure.js","SQL injection detection.js","Telerik Using Poor Crypto.js","Upload form discovery.js","X-Powered-By_header_checker.js"]
    headers = {
        "Accept" : "application/json"
    }
    for i in script:
        response = requests.get(f"{url}/JSON/script/action/enable/?apikey={api_key}&scriptName={i}",headers=headers)
        if response.status_code == "200":
            data = response.json()
            print(i,f": {data}")
        else:
            print(f"enabling script {i} failed")


def forcedUser(url,api_key):
    headers = {
        'Accept': 'application/json',
        'X-ZAP-API-Key': api_key
    }

    response = requests.get(f"{url}/JSON/forcedUser/action/setForcedUserModeEnabled/", params={
        'boolean': 'true'
    }, headers = headers)

    return response.json()

def forcedUserdisable(url,api_key):
    headers = {
        'Accept': 'application/json',
        'X-ZAP-API-Key': api_key
    }

    response = requests.get(f"{url}/JSON/forcedUser/action/setForcedUserModeEnabled/", params={
        'boolean': 'false'
    }, headers = headers)

    return response.json()




def attack_startup(url,api_key,bool):
    headers = {
    "Accept" : "application/json"
    }

    response = requests.get(f"{url}/JSON/ascan/action/setOptionAllowAttackOnStart/?apikey={api_key}&Boolean={bool}",headers)

    return response.json()


def attack_mode(url,api_key,mode):
        try:
            headers = {
                "Accept" : "application/json"
            }
            response = requests.get(f"{url}/JSON/core/action/setMode/?apikey={api_key}&mode={mode}",headers=headers)
            print(response.content)
        except Exception as e:
            print("failed to change mode:", e)


def start_zap(url, api_key):
    try:
        os.system(f"zaproxy -config api.key={api_key} -port 11111 &")
        time.sleep(80)
        print("ZAP started in the background.")
    except Exception as e:
        print("Failed to start ZAP:", e)


def stop_zap(url,api_key):
    response = requests.get(f"{url}/JSON/core/action/shutdown/?apikey={api_key}")
    if response.status_code == "200":
        print("shutdown successful")
    else:
        print("error",response.json())


def check_zap_running(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error if the response status isn't 2xx
        if response.status_code == 200:
            print("ZAP is running")
    except requests.exceptions.RequestException as e:
        print("ZAP is not running:", e)

""" zap automation """



def automation(url,api_key,path):
    try:
        headers = {
            "Content-Type" : "application/x-www-form-urlencoded",
            "Accept" : "application/json"
        }
        data = {
            "apikey" : api_key,
            "filePath": path
        }
        response = requests.post(f"{url}/JSON/automation/action/runPlan/",headers=headers,data=data)

        print("automation build started")
        plan_id = response.json().get("planId")
        check_auto(url,api_key,plan_id)
        print("stopping zap")
        stop_zap(url,api_key)
        print(response.content)
    except Exception as e:
        print("Failed to start ZAP:", e)







def check_auto(url,api_key,id):
    try:
        while True:
            headers = {
                "Accept" : "application/json"
            }
            response = requests.get(f"{url}/JSON/automation/view/planProgress/?apikey={api_key}&planId={id}",headers=headers)
            progress = response.json()
            if "finished" in progress and progress["finished"]:
                print("Automation finished")
                break
        print("process is still running this is for debuging")
        time.sleep(600)
    except Exception as e:
        print("failed to check automation progress:", e)

if __name__ == "__main__":
    main()



