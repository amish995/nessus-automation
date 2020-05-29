from argparse import *
from copy import deepcopy
import csv
from csv import QUOTE_ALL

parser = ArgumentParser(
    formatter_class=RawDescriptionHelpFormatter,
    description=__doc__
)

parser.add_argument('-i', metavar='INPUT', help='SSH Nessus Output', required=True)
args = parser.parse_args()

nessus_out = csv.DictReader(open(args.i))

nessus_dict = dict()

WEAK_KEY = ('diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1')
WEAK_ENC = ('128', '192', 'arcfour', 'aes256-cbc', '3des', 'cast128', 'blowfish')
WEAK_MAC = ('sha1', 'md5', 'ripemd', 'umac-64', 'umac-128')
WEAK_HKA = ['dss']

def parse_input():
    for row in nessus_out:
        nessus_dict[row['Host'], row['Protocol'], row['Port']] = row['Plugin Output']

def parse_ssh(data_in):
    for IP in data_in:
        plugin_out = data_in[IP]
        # print (plugin_out)
        cipher_data = plugin_out.split("the following encryption algorithm with the server : \n")[1]
        cipher_data = cipher_data.split("\nThe server supports the following options for compression_algorithms_client_to_server : ")[0]

        result = dict()

        ssh_blocks = cipher_data.split('The server supports the following options for ')
        ssh_blocks = [x for x in ssh_blocks if x.strip() != ""]

        for s in ssh_blocks:
            lines = [x for x in s.split('\n') if x.strip() != '']
            key = lines[0].strip()
            value = []
            breaker = '  '
            for i in lines:
                if i.startswith(breaker):
                    value.append(i.strip())
            result[key] = value
        data_in[IP] = result
        # print(result)
    return data_in

def remove_if_not_weak(algorithms, weak, debug = False):
    algo = deepcopy(algorithms)
    for a in algo:
        if debug == True:
            print(a)
        remove = True
        for w in weak:
            if w in a:
                if debug == True:
                    print(w, a)
                remove = False
                break
        if remove:
            algorithms.remove(a)
    return algorithms


def flag_ssh(data_in):
    for k, v in data_in.items():
        v['kex_algorithms :'] = remove_if_not_weak(v['kex_algorithms :'], WEAK_KEY)
        v['server_host_key_algorithms :'] = remove_if_not_weak(v['server_host_key_algorithms :'], WEAK_HKA)  
        v['encryption_algorithms_client_to_server :'] = remove_if_not_weak(v['encryption_algorithms_client_to_server :'], WEAK_ENC)
        v['encryption_algorithms_server_to_client :'] = remove_if_not_weak(v['encryption_algorithms_server_to_client :'], WEAK_ENC)
        v['mac_algorithms_client_to_server :'] = remove_if_not_weak(v['mac_algorithms_client_to_server :'], WEAK_MAC)
        v['mac_algorithms_server_to_client :'] = remove_if_not_weak(v['mac_algorithms_server_to_client :'], WEAK_MAC)
        data_in[k] = v
    
    return data_in

def transform_data(data_in):
    for k in data_in:
        issue = ""
        for key, val in data_in[k].items():
            issue += key + "\n"
            for data in val:
                issue += data + "\n"
        data_in[k] = issue
    return data_in

if __name__ == '__main__':
    parse_input()
    parsed_out = parse_ssh(nessus_dict)
    flagged_out = flag_ssh(parsed_out)
    trans_data = transform_data(flagged_out)

    # print (trans_data)
    
    with open('SSH_Issues.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP", "Protocol", "Port", "Weak Algos"])
        for k, v in trans_data.items():
            writer.writerow([k[0], k[1], k[2], v])