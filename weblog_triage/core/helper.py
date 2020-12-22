from collections import Counter
import re


def find_http_method(line):
    method_list = ['GET', 'CONNECT','HEAD','TRACE','POST', 'PUT','DELETE','PATCH',
                   'OPTIONS','PROPFIND','PROPPATCH','COPY','MOVE','QUIT','LOCK','UNLOCK']
    method_found = None
    for method in method_list:
        if re.search(method,line):
            method_found = method
    return method_found


def find_request():
    print("Nothing yet!")


class FreqCounter():
    def __init__(self,total_log_requests):
        self.total_log_requests = total_log_requests
        self.total_repeated_requests = 0
        self.ips_with_high_frequency = []
        self.list_total_ips = set()
        self.ips_freq_dict = dict()
        self.method_freq_dict = dict()
        self.status_freq_dict = dict()
        self.user_agent_freq_dict = dict()
        self.size_request_freq_dict = dict()

    def freq_analyzer(self, log_request_list):
        ip_list = []
        status_list = []
        method_list = []
        user_agent_list = []
        byte_size_list = []
        for i in log_request_list:
            ip_list.append(i.ip)
            method_list.append(i.http_method)
            status_list.append(i.http_status)
            user_agent_list.append(i.user_agent)
            byte_size_list.append(i.size_request)
        self.ips_freq_dict = Counter(ip_list)
        self.method_freq_dict = Counter(method_list)
        self.status_freq_dict = Counter(status_list)
        self.user_agent_freq_dict = Counter(user_agent_list)
        self.size_request_freq_dict = Counter(byte_size_list)

    def get_method_freq_dict(self):
        return self.method_freq_dict

    def _print_freq_summary(self, arg):
        if arg == "IP's":
            arg_req_dict = self.ips_freq_dict
        elif arg == "User Agent":
            arg_req_dict = self.user_agent_freq_dict
        elif arg == "HTTP Methods":
            arg_req_dict = self.method_freq_dict
        elif arg == "Status Methods":
            arg_req_dict = self.status_freq_dict
        elif arg == "Request size":
            arg_req_dict = self.size_request_freq_dict
        print("Freq summary of: " +arg)
        for item, amount in arg_req_dict.items():
            print("\t {} ({})".format(item, amount))

    def print_freq_summary(self):
        self._print_freq_summary("IP's")
        self._print_freq_summary("User Agent")
        self._print_freq_summary("HTTP Methods")
        self._print_freq_summary("Status Methods")
        self._print_freq_summary("Request size")

