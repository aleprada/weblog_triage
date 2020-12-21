class LogStatistics():
    def __init__(self):
        self.total_log_requests = 0
        self.total_repeated_requests = 0
        self.ips_with_high_frequency = []
        self.list_total_ips = set()
        self.dict_ips_freq = dict()

    def get_all_ips(self):
        return self.list_total_ips

    def get_ips_freq(self):
        return self.dict_ips_freq

    def check_all_ips(self, logrequests_list):
        for ip in logrequests_list:
            self.list_total_ips.add(ip)
        return self.list_total_ips

    def count_freq_ip(self, ip, logrequests_list):
        count = 0
        for ip in logrequests_list:
            if logrequests_list.ip == ip:
                count = count + 1
        return count

    def get_frequency_ips(self, list_total_ip, logrequests_list):
        for ip in list_total_ip:
            freq = LogStatistics.count_freq_ip(ip, logrequests_list)
            self.dict_ips_freq.append(ip, freq)
        return self.dict_ips_freq