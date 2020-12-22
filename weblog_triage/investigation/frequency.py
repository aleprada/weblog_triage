from weblog_triage.core.helper import FreqCounter


#Look for PUT, DELETE and other non very used methods.
def low_freq_http_methods(method_freq_dict, log_request_list):
    method_list = ['GET', 'CONNECT', 'HEAD', 'TRACE', 'POST', 'PUT', 'DELETE', 'PATCH',
                   'OPTIONS', 'PROPFIND', 'PROPPATCH', 'COPY', 'MOVE', 'QUIT', 'LOCK', 'UNLOCK']
    for method, times in method_freq_dict.items():
        if "PUT" == method:
            #look for PUT requests and store them
            print("looking for PUT values")
        elif "DELETE" == method:
            #look for DELETE request and store them
            print("looking for DELETE values")
        elif method not in method_list:
            #look for uncommon or fuzzed HTTP Methods
            print("looking for uncommon values")


def low_freq_ips(ips_freq_dict, log_request_list):
    print("looking for http")
    #look for low frequency IPs

def analyze_by_freq(log_request_list):
    freq_counter = FreqCounter(len(log_request_list))
    freq_counter.freq_analyzer(log_request_list)
    low_freq_http_methods(freq_counter.method_freq_dict, log_request_list)


