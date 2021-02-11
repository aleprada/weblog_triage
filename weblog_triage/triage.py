import argparse
from weblog_triage.core.helper import parse_log
from weblog_triage.investigation.patterns import look_for_attack_patterns
from weblog_triage.investigation.frequency import analyze_by_freq
from weblog_triage.investigation.iocs import complete_ioc_analysis,analyze_iocs, look_for_ioc_in_misp
from weblog_triage.core.reporting import create_report
from weblog_triage.core.alerts import AlertType

from sys import exit


def main():
    # Create ASCII ART
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filepath", help="Path of the file to analyze.", required=True)
    parser.add_argument("-i", "--iocs", help="Look for indicators of compromise stored in a txt. file.")
    parser.add_argument("-m", "--misp", help="Look for indicators of compromise stored in a txt. file.", action='store_true')
    parser.add_argument("-a", "--attacks", help="Look for investigation of common attacks such as XSS, SQLi, Backdoors,etc.", action='store_true')
    parser.add_argument("-c", "--count", help="Frequency analysis of IPs, domain names or HTTP status for finding anomalous behaviour.", action='store_true')
    parser.add_argument("-t", "--total", help=" Complete analysis of the logs analysing Frequency, IoCs and Attack Patterns")

    args = parser.parse_args()

    if args.filepath:
        log_request_list = parse_log(args.filepath)
    else:
        print("[!] Please, introduce the filepath of the log to analyze.")

    if args.iocs:
        iocs_file = args.iocs
        alerts_ioc= analyze_iocs(iocs_file, log_request_list)
        create_report(alerts_ioc, False, AlertType.IOCs)
        exit(0)
    elif args.misp:
        alert_attack_patterns = look_for_ioc_in_misp(False, log_request_list)
        create_report(alert_attack_patterns,  AlertType.IOCs)
        exit(0)
    elif args.attacks:
        alert_attack_patterns = look_for_attack_patterns(log_request_list)
        create_report(alert_attack_patterns, False, AlertType.Pattern)
        exit(0)
    elif args.count:
        alerts_list_freq = analyze_by_freq(log_request_list)
        create_report(alerts_list_freq, False, AlertType.FREQUENCY)
        exit(0)
    elif args.total:
        total_alerts = []
        iocs_file = args.total
        alerts_list_freq = analyze_by_freq(log_request_list)
        if len(alerts_list_freq)>0:
            total_alerts = alerts_list_freq
        alerts_iocs = complete_ioc_analysis(iocs_file, log_request_list, False)
        if len(alerts_iocs) > 0:
            total_alerts = total_alerts + alerts_iocs
        alerts_patterns = look_for_attack_patterns(log_request_list)
        if len(alerts_patterns)>0:
            total_alerts = total_alerts + alerts_patterns
        create_report(total_alerts,True)
        exit(0)
    else:
        print("[!] Invalid option. Please type -h for checking the valid options.")
        exit(1)


if __name__ == "__main__":
    main()

