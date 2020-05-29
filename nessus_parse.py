from argparse import *
import csv
from csv import QUOTE_ALL

parser = ArgumentParser(
    formatter_class=RawDescriptionHelpFormatter,
    description=__doc__
)

parser.add_argument('-i', metavar='INPUT', help='SSL Nessus Output', required=True)
args = parser.parse_args()

nessus_out = csv.DictReader(open(args.i))

nessus_dict = dict()

WEAK_TLS = ('128', 'DES-CBC3', 'SHA ', '1024')

def parse_input():
    for row in nessus_out:
        nessus_dict[row['Host'], row['Protocol'], row['Port']] = row['Plugin Output']

def get_weak(ciphers):
    result = []
    for i in ciphers:
        for j in WEAK_TLS:
            if j in i:
                result.append(i)
                break
    return result

def parse_ssl(data_in):
    for IP in data_in:
        plugin_out = data_in[IP]
        # print (plugin_out)
        cipher_data = plugin_out.split("Each group is reported per SSL Version.\n\n")[1]
        cipher_data = cipher_data.split("\n\nThe fields above are :")[0]

        result = dict()

        ssl_blocks = cipher_data.split('SSL Version : ')
        ssl_blocks = [x for x in ssl_blocks if x.strip() != ""]

        for s in ssl_blocks:
            lines = [x for x in s.split('\n') if x.strip() != '']
            key = lines[0].strip()
            value = []
            breaker = '    '
            for i in lines:
                if i.startswith(breaker):
                    sanitized = i.split(breaker)[1]
                    if sanitized.startswith('Name') or sanitized.startswith('----'):
                        continue
                    else:
                        value.append(sanitized.split()[0] + " ")
            result[key] = value
        data_in[IP] = result
        # print(result)
    return data_in

def flag_ssl(data_in):
    for IP in data_in:
        ciphers = data_in[IP]
        weak_ciphers = {}
        for SSL in ciphers:
            if SSL == "SSLv2":
                weak_ciphers["SSLv2:"] = ["All"]
            elif SSL == "SSLv3":
                weak_ciphers["SSLv3:"] = ["All"]
            elif SSL == "TLSv1":
                weak_ciphers["TLSv1.0:"] = ["All"]
            elif SSL == "TLSv11":
                weak_ciphers["TLSv1.1:"] = ["All"]
            elif SSL == "TLSv12":
                weak_ciphers["TLSv1.2:"] = get_weak(ciphers[SSL])
        data_in[IP] = weak_ciphers
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
    parsed_out = parse_ssl(nessus_dict)
    flagged_out = flag_ssl(parsed_out)
    trans_data = transform_data(flagged_out)

    # print (trans_data)
    
    with open('SSL_Issues.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP", "Protocol", "Port", "Weak Algos"])
        for k, v in trans_data.items():
            writer.writerow([k[0], k[1], k[2], v])