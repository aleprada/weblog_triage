#ToDo add reporting functions here (create folders by approach, integration with dashboards)
import os
import datetime
from weblog_triage.core.alerts import AlertReason


def create_folder(path,name):
    try:
        os.makedirs(path+name)
    except OSError:
        print("Creation of the directory %s failed" % path+name)


def add_alert_into_file(name, alert):
    try:
        with open(name, "a") as f:
                f.write(alert.request_str + "\n")
    except AttributeError as e:
        print("Exception! :" + str(e))


def create_report(alert_list,report_type):
    date_report = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    path = "./reports/"+date_report+"/"
    create_folder(path, report_type) #path should be in config file.
    path_file = path+report_type+"/"
    for a in alert_list:
        if a.reason == (AlertReason.UNCOMMON or AlertReason.DELETE or AlertReason.PUT):
            add_alert_into_file(path_file+"uncommon_methods.txt",a)
        elif a.reason == AlertReason.SUCCESSFUL:
            add_alert_into_file(path_file+"successful_2xx.txt",a)
        elif a.reason == AlertReason.USER_AGENT:
            add_alert_into_file(path_file+"user_agent_suspicious.txt",a)
        elif a.reason == AlertReason.FREQ_IP:
            add_alert_into_file(path_file+"low_freq_ips.txt",a)
        elif a.reason == AlertReason.BYTE_SIZE:
            add_alert_into_file(path_file+"low_freq_low_bytes.txt",a)
    print("\t[+] Successfully report created at " +path_file)








