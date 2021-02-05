from pymisp import PyMISP, MISPEvent, MISPAttribute
from weblog_triage.core.alerts import Alert, AlertReason,AlertType
from weblog_triage.config.config import config_parser
import logging;


def look_for_ioc(ioc, log_request_list):
    result_list = []
    for r in log_request_list:
        if ioc in (r.ip or r.url or r.user_agent):
            a = Alert(AlertType.IOCs, AlertReason.IOC, r.raw_request)
            result_list.append(a)
    return result_list


def analyze_iocs(iocs_filepath, log_request_list):
    print("[*] Analysis of IoC's ")
    print("[!] IoCs found: ")
    result_list = []
    with open(iocs_filepath) as fp:
        for cnt, ioc in enumerate(fp):
            found_reqs =look_for_ioc(ioc.rstrip("\n"), log_request_list)
            result_list = result_list + found_reqs
    print("\t [!] in IoCs list : " + str(len(result_list)))
    return result_list


def look_for_misp_ioc(ioc, request):
    ioc_misp_found = False
    if ioc in (request.ip or request.url or request.user_agent):
        ioc_misp_found = True
    return ioc_misp_found


def look_for_ioc_in_misp(proxies_usage, log_request_list):
    result_list = []
    if proxies_usage:
        proxies = {}
        proxies ['http'] = config_parser("MISP","proxy")
        proxies ['https'] = config_parser("MISP","proxy")
        misp = PyMISP(config_parser("MISP","url"), config_parser("MISP","key"), False, 'json', proxies=proxies)
    else:
        misp = PyMISP(config_parser("MISP","url"), config_parser("MISP","key"), False, 'json')

    logging.getLogger('pymisp').setLevel(logging.DEBUG)
    events = misp.events()
    print("[!] Total MISP events:"+ str(len(events)))
    potential_iocs = {}
    for e in events:
        event = misp.get_event(e.get("id"))
        atts = event.get("Event").get("Attribute")
        for a in atts:
            if a["type"] in ["url", "ip-dst", "ip-dst|port", "domain", "ip-src"]:
                key = event.get("Event").get("id")+"_"+a["type"]
                potential_iocs[key] = a["value"]

    for r in log_request_list:
        for k, v in potential_iocs.items():
            if look_for_misp_ioc(v,r):
                a = Alert(AlertType.IOCs, AlertReason.MISP, r.raw_request)
                a.add_ioc_detected(v)
                a.add_misp_event_id(k.split("_")[0])
                result_list.append(a)

    return result_list

def complete_ioc_analysis(iocs_filepath, log_request_list, proxies_usage):
    print("[*] Analysis of IoC's ")
    print("[!] IoCs found: ")
    result_ioc_list = analyze_iocs(iocs_filepath, log_request_list)
    print("\t [!] in IoCs list : " + str(len(result_ioc_list)))
    if len(config_parser("MISP", "url"))> 0:
        result_misp_iocs = look_for_ioc_in_misp(proxies_usage, log_request_list)
        print("\t [!] in MISP : " + str(len(result_misp_iocs)))
    return result_ioc_list + result_misp_iocs


