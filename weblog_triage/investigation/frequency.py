from weblog_triage.core.helper import FreqCounter
from weblog_triage.core.alerts import AlertReason, AlertType, Alert


def look_for_IPS(IP, request_list):
    result_list = []
    for r in request_list:
        if r.ip == IP:
            a = Alert(AlertType.FREQUENCY, AlertReason.FREQ_IP, r.raw_request)
            result_list.append(a)
    return result_list


#Look for PUT, DELETE and other non very used methods.
def low_freq_http_methods(method_freq_dict, log_request_list):
    method_list = ['GET', 'CONNECT', 'HEAD', 'TRACE', 'POST', 'PUT', 'DELETE', 'PATCH',
                   'OPTIONS', 'PROPFIND', 'PROPPATCH', 'COPY', 'MOVE', 'QUIT', 'LOCK', 'UNLOCK']
    alert_list = []
    for req in log_request_list:
        if req.http_method is "PUT":
            #look for PUT requests and store them
            print("looking for PUT values")
            a = Alert(AlertType.FREQUENCY, AlertReason.PUT,req)
            alert_list.append(a)
        elif req.http_method is "DELETE":
            #look for DELETE request and store them
            print("looking for DELETE values")
            b = Alert(AlertType.FREQUENCY, AlertReason.DELETE, req)
            alert_list.append(b)
        elif req.http_method not in method_list:
            #look for uncommon or fuzzed HTTP Methods
            print("looking for uncommon values")
            c = Alert(AlertType.FREQUENCY, AlertReason.UNCOMMON, req)
            alert_list.append(c)
        else:
            continue

    return alert_list



def low_freq_ips(ips_freq_dict, log_request_list):
    total_alert_list = []
    print("looking for IPs with low frequency")
    #look for low frequency IPs
    #loop dictionary and find out a good threshold for stuying requests.
    for item, counter in ips_freq_dict.items():
        if counter < 60: #magic number. Better make it configurable.
            alert_list = look_for_IPS(item, log_request_list )
            total_alert_list = total_alert_list + alert_list

    return total_alert_list


def analyze_by_freq(log_request_list):
    total_alert_list = []
    freq_counter = FreqCounter(len(log_request_list))
    freq_counter.freq_analyzer(log_request_list)
    alerts_methods = low_freq_http_methods(freq_counter.method_freq_dict, log_request_list)
    alerts_ips = low_freq_ips(freq_counter.ips_freq_dict, log_request_list)
    total_alert_list = alerts_methods + alerts_ips
    return total_alert_list


