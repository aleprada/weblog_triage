import argparse
import os
from weblog_triage.core.parser import LogRequest
from weblog_triage.core.helper import FreqCounter
from weblog_triage.investigation.frequency import analyze_by_freq
from clfparser import CLFParser


def parse_log(filepath):
    log_request_list = []
    if os.path.exists(filepath):
        try:
            with open(filepath) as f:
                log = f.readlines()
                for line in log:
                    print(line)
                    clfDict = CLFParser.logDict(line.rstrip())
                    ip = clfDict.get("h")
                    timestamp = clfDict.get("t")
                    request_splitted = clfDict.get("r").replace('"','').split(" ")
                    status_request = clfDict.get("s")
                    size_request = clfDict.get("b")
                    referer = clfDict.get("Referer")
                    user_agent = clfDict.get("Useragent")
                    if len(request_splitted) > 1:
                        method = request_splitted[0]
                        url = request_splitted[1]
                        log_request_line = LogRequest(ip=ip, timestamp=timestamp, url=url, http_method=method.replace('"',""),
                                                      http_status=status_request, size_request=size_request,
                                                      referer_url=referer, user_agent=user_agent, raw_request=line.rstrip())
                    else:
                        bad_request = clfDict.get("r").replace('"','')
                        log_request_line = LogRequest(ip=ip, timestamp=timestamp, url=None, http_method=None,
                                                      http_status=status_request, size_request=size_request,
                                                      referer_url=referer, user_agent=user_agent, raw_request=line.rstrip())
                        log_request_line.add_bad_method(bad_request)

                    log_request_list.append(log_request_line)

            print("Total log request objects: "+str(len(log_request_list)))
            print("Total log lines: "+str(len(log)))
            return log_request_list

        except:
            print("[!] There was an error while reading the file.")
            print(line)
    else:
        print("[!] The file doesn't exist")


def main():
    # Create ASCII ART
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filepath", help="Path of the file to analyze.")
    parser.add_argument("-i", "--ioc", help="Look for indicators of compromise.", action="store_true")
    parser.add_argument("-a", "--attacks", help="Look for investigation of common attacks such as XSS, SQLi, LFI,etc.",
                        action="store_true")
    parser.add_argument("-c", "--count",
                        help="Count artifacts such as IPs, domain names or HTTP status for finding anomalous behaviour.",
                        action="store_true")
    parser.add_argument("-r", "--results", help=" Path for storing the results.", action="store_true")

    args = parser.parse_args()
    if args.filepath:
        # capture exception of read file
        log_request_list = parse_log(args.filepath)
        log_stats = FreqCounter(len(log_request_list))
        print(len(log_request_list))
        dict_ips = log_stats.ips_counter(log_request_list)
        print(dict_ips)
    else:
        print("[!] Please, introduce the filepath of the log to analyze.")

    if args.ioc:
        #call IoCs analyzer
        print("ioc")
    elif args.attacks:
        #call attack patterns analyzer
        print("attack patterns")
    elif args.count:
        #call frequency analyzers.
        print("frequency")


if __name__ == "__main__":
    # main()
    log_request_list = parse_log("/home/alejandro.prada/VisualStudioProyects/weblogs_autotriage/datasets/logs/access_log_1")
    analyze_by_freq(log_request_list)
