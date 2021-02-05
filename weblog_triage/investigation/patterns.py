from weblog_triage.config.config import get_attack_patterns
from weblog_triage.core.alerts import Alert, AlertReason, AlertType
import re


def look_for_sqli(requestlist):
    alerts_sqli=[]
    sqli_patterns = get_attack_patterns("sqli")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in sqli_patterns.items():
                if v in url:
                    a = Alert(AlertType.Pattern, AlertReason.SQLI, req.raw_request)
                    alerts_sqli.append(a)
    return alerts_sqli


def look_for_xss(requestlist):
    alerts_xss=[]
    sqli_patterns = get_attack_patterns("xss")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in sqli_patterns.items():
                if v in url:
                    a = Alert(AlertType.Pattern, AlertReason.XSS, req.raw_request)
                    alerts_xss.append(a)
    return alerts_xss

def look_for_backdoors(requestlist):
    alerts_backdoors = []
    alerts_patterns = get_attack_patterns("backdoor")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in alerts_patterns.items():
                if v in url:
                    a = Alert(AlertType.Pattern, AlertReason.BACKDOOR, req.raw_request)
                    alerts_backdoors.append(a)
    return alerts_backdoors


def look_for_cmd_inj(requestlist):
    alerts_cmdinj = []
    alerts_patterns = get_attack_patterns("cmd_inj")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in alerts_patterns.items():
                if v in url:
                    a = Alert(AlertType.Pattern, AlertReason.CMD_INJ, req.raw_request)
                    alerts_cmdinj.append(a)
    return alerts_cmdinj


def look_for_common_misconfigs(requestlist):
    alerts_misconf = []
    alerts_patterns = get_attack_patterns("misconf")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in alerts_patterns.items():
                if v in url:
                    a = Alert(AlertType.Pattern, AlertReason.MISCONF, req.raw_request)
                    alerts_misconf.append(a)
    return alerts_misconf


def look_for_admin_login(requestlist):
    alerts_admin = []
    alerts_patterns = get_attack_patterns("admin")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in alerts_patterns.items():
                if v in url:
                    a = Alert(AlertType.Pattern, AlertReason.ADMINSITE, req.raw_request)
                    alerts_admin.append(a)
    return alerts_admin


def look_for_path_traversal(requestlist):
    alerts_pathtrav = []
    alerts_patterns = get_attack_patterns("path_traversal")
    for req in requestlist:
        url = req.url
        if url is not None:
            for k, v in alerts_patterns.items():
                encod="%"+v
                if encod in url:
                    a = Alert(AlertType.Pattern, AlertReason.PATH_TRAV, req.raw_request)
                    alerts_pathtrav.append(a)
    return alerts_pathtrav


def look_for_base64(requestlist):
    regex = "[a-z0-9+/]+={2}"
    alerts_base64 = []
    for req in requestlist:
        url = req.url
        if url is not None:
            matches = re.findall(regex,url)
            if len(matches)> 0:
                a = Alert(AlertType.Pattern, AlertReason.BASE64, req.raw_request)
                alerts_base64.append(a)
    return alerts_base64


def look_for_encoding(requestlist):
    regex = "%[a-f0-9]{2}%"
    alerts_enconding = []
    for req in requestlist:
        url = req.url
        if url is not None:
            matches = re.findall(regex,url)
            if len(matches)> 0:
                a = Alert(AlertType.Pattern, AlertReason.ENCODING, req.raw_request)
                alerts_enconding.append(a)
    return alerts_enconding


def long_url(requestlist):
    regex = "(\/|\.)([a-z0-9-]{30,75})(\/|\.)"
    alerts_long_url= []
    for req in requestlist:
        url = req.url
        if url is not None:
            matches = re.findall(regex,url)
            if len(matches)> 0:
                a = Alert(AlertType.Pattern, AlertReason.LONG_URL, req.raw_request)
                alerts_long_url.append(a)
    return alerts_long_url


def look_for_attack_patterns(request_list):
    print("[*] Analysis of Attack Patterns ")
    result_sqli = look_for_sqli(request_list)
    print("[!] Attack patterns found: ")
    print("\t [!] SQLi : "+str(len(result_sqli)))
    result_xss = look_for_xss(request_list)
    print("\t [!] XSS : " + str(len(result_xss)))
    result_backdoor = look_for_backdoors(request_list)
    print("\t [!] Backdoor : " + str(len(result_backdoor)))
    result_cmd_inj = look_for_cmd_inj(request_list)
    print("\t [!] Command Injection : " + str(len(result_cmd_inj)))
    result_misconf = look_for_common_misconfigs(request_list)
    print("\t [!] Misconfiguration : " + str(len(result_misconf)))
    result_admin_site = look_for_admin_login(request_list)
    print("\t [!] Admin site : " + str(len(result_admin_site)))
    result_path_trav=look_for_path_traversal(request_list)
    print("\t [!] Path traversal : " + str(len(result_path_trav)))
    result_encoded = look_for_encoding(request_list)
    print("\t [!] Encoding: " + str(len(result_encoded)))
    result_b64 = look_for_base64(request_list)
    print("\t [!] Base64: " + str(len(result_b64)))
    result_long_url= long_url(request_list)
    print("\t [!] Long URL: " + str(len(result_long_url)))
    total_alerts= result_sqli + result_xss + result_backdoor + result_cmd_inj + result_misconf + result_admin_site + result_path_trav + result_encoded + result_b64 + result_long_url
    return total_alerts
