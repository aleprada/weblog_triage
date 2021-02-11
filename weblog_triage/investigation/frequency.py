from weblog_triage.core.helper import FreqCounter
from weblog_triage.core.alerts import AlertReason, AlertType, Alert
from IPy import IP


def look_for_ips(ip, request_list):
    result_list = []
    for r in request_list:
        if r.ip == ip:
            a = Alert(AlertType.FREQUENCY, AlertReason.FREQ_IP, r.raw_request)
            result_list.append(a)
    return result_list


def look_for_user_agents(user_agent, request_list):
    result_list = []
    for r in request_list:
        if r.user_agent == user_agent:
            a = Alert(AlertType.FREQUENCY, AlertReason.USER_AGENT, r.raw_request)
            result_list.append(a)
    return result_list


def look_for_low_byte_sizes(byte_size, request_list):
    result_list = []
    for r in request_list:
        if r.size_request == byte_size:
            a = Alert(AlertType.FREQUENCY, AlertReason.BYTE_SIZE, r.raw_request)
            result_list.append(a)
    return result_list


# Look for PUT, DELETE and other non very used methods.
def low_freq_http_methods(method_freq_dict, log_request_list):
    method_list = ['GET', 'CONNECT', 'HEAD', 'TRACE', 'POST', 'PUT', 'DELETE', 'PATCH',
                   'OPTIONS', 'PROPFIND', 'PROPPATCH', 'COPY', 'MOVE', 'QUIT', 'LOCK', 'UNLOCK']
    alert_list = []
    for req in log_request_list:
        if req.http_method is "PUT":
            #look for PUT requests and store them
            a = Alert(AlertType.FREQUENCY, AlertReason.PUT,req.raw_request)
            alert_list.append(a)
        elif req.http_method is "DELETE":
            #look for DELETE request and store them
            b = Alert(AlertType.FREQUENCY, AlertReason.DELETE, req.raw_request)
            alert_list.append(b)
        elif req.http_method not in method_list:
            #look for uncommon or fuzzed HTTP Methods
            c = Alert(AlertType.FREQUENCY, AlertReason.UNCOMMON, req.raw_request)
            alert_list.append(c)
        else:
            continue

    return alert_list


def check_private_ip(ip):
    ip_checked = IP(ip)
    if ip_checked.iptype() == 'PRIVATE':
        private_ip = True
    else:
        private_ip = False

    return private_ip


def low_freq_ips(ips_freq_dict, log_request_list):
    total_alert_list = []
    #look for low frequency IPs
    #loop dictionary and find out a good threshold for stuying requests.
    for ip, counter in ips_freq_dict.items():
        if counter < 60 and not check_private_ip(ip): #magic number. Better make it configurable.
            alert_list = look_for_ips(ip, log_request_list)
            total_alert_list = total_alert_list + alert_list

    return total_alert_list


def low_freq_user_agents(ua_freq_dict, log_request_list):
    total_alert_list = []
    #look for low frequency User Agents
    #loop dictionary and find out a good threshold for stuying requests.
    for item, counter in ua_freq_dict.items():
        if counter < 60 and "Mozilla" in item: #magic number. Better make it configurable. Add more keywords besides Mozilla
            alert_list = look_for_user_agents(item, log_request_list )
            total_alert_list = total_alert_list + alert_list

    return total_alert_list


def successful_http_request(log_request_list):
    total_alert_list = []
    for r in log_request_list:
        if r.http_status.startswith("2"):
            a = Alert(AlertType.FREQUENCY, AlertReason.SUCCESSFUL,r.raw_request)
            total_alert_list.append(a)
    return total_alert_list


# Look for low frequency requests with a low number of bytes

def byte_size(byte_size_freq_dict, log_request_list):
    total_alert_list = []
    # look for low frequency User Agents
    # loop dictionary and find out a good threshold for stuying requests.
    for item, counter in byte_size_freq_dict.items():
        try:
            if counter < 60 and int(item) < 50:  # magic number. Better make it configurable. Frequency and size
                alert_list = look_for_low_byte_sizes(item, log_request_list)
                total_alert_list = total_alert_list + alert_list
        except ValueError as e:
            print("\t [?] Error casting the following size: "+str(e) + " "+item)
            continue

    return total_alert_list


def analyze_by_freq(log_request_list):
    print("[*] Analysis of frequency ")
    freq_counter = FreqCounter(len(log_request_list))
    freq_counter.freq_analyzer(log_request_list)
    print("[!] Alerts by frequency: ")
    alerts_methods = low_freq_http_methods(freq_counter.method_freq_dict, log_request_list)
    print("\t [!] Low frequency suspicious HTTP methods : "+str(len(alerts_methods)))
    alerts_ips = low_freq_ips(freq_counter.ips_freq_dict, log_request_list)
    print("\t [!] Low frequency suspicious IP's : "+str(len(alerts_ips)))
    alerts_success_status = successful_http_request(log_request_list)
    print("\t [!] Low frequency 2XX status: "+str(len(alerts_success_status)))
    alerts_user_agent = low_freq_user_agents(freq_counter.user_agent_freq_dict, log_request_list)
    print("\t [!] Low frequency User agents: "+str(len(alerts_user_agent)))
    alerts_byte_size = byte_size(freq_counter.size_request_freq_dict, log_request_list)
    print("\t [!] Low frequency byte size: "+str(len(alerts_byte_size)))
    total_alert_list = alerts_methods + alerts_ips + alerts_success_status + alerts_user_agent + alerts_byte_size
    return total_alert_list


