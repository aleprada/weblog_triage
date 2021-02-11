import os
import datetime
from weblog_triage.core.alerts import AlertReason, AlertType

def create_folder(path,name):
    try:
        os.makedirs(path+name)
    except OSError:
        print("Creation of the directory %s failed" % path+name)


def init_report():
    date_report = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    path = "./reports/" + date_report + "/"
    create_folder(path, "frequency")
    create_folder(path, "iocs")
    create_folder(path, "attack_patterns")
    return path


def add_alert_into_file(name, alert):
    try:
        with open(name, "a") as f:
            f.write(alert.request_str + "\n")
    except AttributeError as e:
        print("Exception! :" + str(e))


def freq_report_summary(path,freq_counter):
    list_dict = []
    try:
        with open(path+"freq_summary.txt", "a") as f:
            list_dict.append(freq_counter.ips_freq_dict)
            list_dict.append(freq_counter.method_freq_dict)
            list_dict.append(freq_counter.status_freq_dict)
            list_dict.append(freq_counter.user_agent_freq_dict)
            list_dict.append(freq_counter.size_request_freq_dict)
            for freq_dict in list_dict:
                f.write("Summary of the item: " +str(freq_dict) +"\n")
                for item, amount in freq_dict.items():
                    f.write("\t {} ({})".format(item, amount)+"\n")
    except AttributeError as e:
        print("Exception! :" + str(e))


def create_report_freq(alert_list, freq_path_file):
    for a in alert_list:
        if a.reason == (AlertReason.UNCOMMON or AlertReason.DELETE or AlertReason.PUT):
            add_alert_into_file(freq_path_file + "uncommon_methods.txt", a)
        elif a.reason == AlertReason.SUCCESSFUL:
            add_alert_into_file(freq_path_file + "successful_2xx.txt", a)
        elif a.reason == AlertReason.USER_AGENT:
            add_alert_into_file(freq_path_file + "user_agent_suspicious.txt", a)
        elif a.reason == AlertReason.FREQ_IP:
            add_alert_into_file(freq_path_file + "low_freq_ips.txt", a)
        elif a.reason == AlertReason.BYTE_SIZE:
            add_alert_into_file(freq_path_file + "low_freq_low_bytes.txt", a)


def create_report_iocs(alert_list, iocs_path_file):
    for a in alert_list:
        if a.reason == (AlertReason.IOC):
            add_alert_into_file(iocs_path_file + "iocs.txt", a)
        elif a.reason == (AlertReason.MISP):
            add_alert_into_file(iocs_path_file + "misp.txt", a)


def create_report_attack_pattern(alert_list, attacks_path_file):
    for a in alert_list:
        if a.reason == (AlertReason.SQLI):
            add_alert_into_file(attacks_path_file + "sqli.txt", a)
        elif a.reason == (AlertReason.XSS):
            add_alert_into_file(attacks_path_file + "xss.txt", a)
        elif a.reason == (AlertReason.BACKDOOR):
            add_alert_into_file(attacks_path_file + "backdoors.txt", a)
        elif a.reason == (AlertReason.CMD_INJ):
            add_alert_into_file(attacks_path_file + "cmd_inj.txt", a)
        elif a.reason == (AlertReason.MISCONF):
            add_alert_into_file(attacks_path_file + "misconfiguration.txt", a)
        elif a.reason == (AlertReason.ADMINSITE):
            add_alert_into_file(attacks_path_file + "admin_login.txt", a)
        elif a.reason == (AlertReason.PATH_TRAV):
            add_alert_into_file(attacks_path_file + "path_traversal.txt", a)
        elif a.reason == (AlertReason.ENCODING):
            add_alert_into_file(attacks_path_file + "encoding.txt", a)
        elif a.reason == (AlertReason.BASE64):
            add_alert_into_file(attacks_path_file + "base64.txt", a)
        elif a.reason == (AlertReason.LONG_URL):
            add_alert_into_file(attacks_path_file + "long_url.txt", a)


def create_report(alert_list, complete_analysis, type=False):
    path_base = init_report()
    freq_path_file = path_base + "frequency/"
    iocs_path_file = path_base + "iocs/"
    attacks_path_file = path_base + "attack_patterns/"
    if complete_analysis == False:
        if type == AlertType.FREQUENCY:
            create_report_freq(alert_list, freq_path_file)
        elif type == AlertType.IOCs:
            create_report_iocs(alert_list, iocs_path_file)
        elif type == AlertType.Pattern:
            create_report_attack_pattern(alert_list, attacks_path_file)
    else:
        create_report_freq(alert_list, freq_path_file)
        create_report_iocs(alert_list, iocs_path_file)
        create_report_attack_pattern(alert_list, attacks_path_file)
    print("[*] Successfully report created at " +path_base)






