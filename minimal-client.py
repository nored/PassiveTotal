#!/usr/bin/env python 
# -*- coding: utf-8 -*-

import requests, csv, json, sys, io, yaml, os.path, argparse

if sys.version_info[0] == 3:
    from io import StringIO
else:
    from io import BytesIO as StringIO

# construct the argument parse and parse the arguments
ap = argparse.ArgumentParser(description='Minimal PassiveTotal Api-Client')
ap.add_argument("-a", "--action", required=True,
	help='''possible arguments:\n
  {action,pdns,whois,ssl,osint,compo}
    \npdns:                Query passive DNS data\n
    \nwhois:               Query WHOIS data\n
    \nssl:                 Query SSL certificate data\n
    \ncomp:                Query Componets\n
    \ntracker:             Query Trakers\n
    \nmalware:             Query Malware data\n
    \nsubd:                Query Subdomain data\n''')
ap.add_argument("-q", "--query", required=True,
	help="query to search for")
args = vars(ap.parse_args())

action = args['action']
query = args['query']

# Define config data
data = {'passiv_total_config': {'api_username': 'e_mail',
                         'api_key': 'value',
                         'base_url': 'https://api.passivetotal.org',
                         'pdns': '/v2/dns/passive',
                         'whois': '/v2/whois',
                         'ssl': '/v2/ssl-certificate/history',
                         'comp': '/v2/host-attributes/components',
                         'tracker': '/v2/host-attributes/trackers',
                         'malware': '/v2/enrichment/malware',
                         'subd': '/v2/enrichment/subdomains'
                         }}

if not os.path.isfile('config'):
    # Write YAML file if not exists
    with io.open('config', 'w', encoding='utf8') as outfile:
        yaml.dump(data, outfile, default_flow_style=False, allow_unicode=True)

# Read YAML file
with open("config", 'r') as stream:
    data_loaded = yaml.load(stream)

data_loaded = data_loaded['passiv_total_config']

username = data_loaded['api_username']
key = data_loaded['api_key']
auth = (username, key)
base_url = data_loaded['base_url']

if data_loaded['api_key'] == 'value':
    sys.exit("Please do: code " + os.path.dirname(os.path.abspath(__file__)) + "/config \nand setup the configuration first!\nYou can \"Copy&Paste\" this command!!!")

def passivetotal_get(endpoint, query):
    url = base_url + endpoint
    data = {'query': query}
    # Important: Specifying json= here instead of data= ensures that the
    # Content-Type header is application/json, which is necessary.
    response = requests.get(url, auth=auth, json=data)
    # This parses the response text as JSON and returns the data representation.
    return response.json()

def whois_to_csv(data):
    if "text" in data:
        second_table= data["text"]
        del data["text"]
    else:
        sys.exit("API Limit reached for today")
    
    first_output = StringIO()
    first_writer = csv.writer(first_output)

    second_output = StringIO()
    second_writer = csv.writer(second_output)

    output = StringIO()

    first_writer.writerow(data.keys())
    first_writer.writerow(data.values())
    second_writer.writerow(["Text:"])
    list = []
    list.append(second_table)
    second_writer.writerow(list)

    first_output.seek(0)
    second_output.seek(0)

    output.write(first_output.read())
    output.write(second_output.read())
    output.seek(0)
    return output.read()

def subd_to_csv(data):
    if "subdomains" in data:
        second_table= data["subdomains"]
        del data["subdomains"]
    else:
        sys.exit("API Limit reached for today")
    
    first_output = StringIO()
    first_writer = csv.writer(first_output)

    second_output = StringIO()
    second_writer = csv.writer(second_output)

    output = StringIO()

    first_writer.writerow(data.keys())
    first_writer.writerow(data.values())
    second_writer.writerow(["Subdomains:"])
    for i in second_table:
        list = []
        list.append(i)
        second_writer.writerow(list)

    first_output.seek(0)
    second_output.seek(0)

    output.write(first_output.read())
    output.write(second_output.read())
    output.seek(0)
    return output.read()

def to_csv(data):
    if "results" in data:
        second_table= data["results"]
        del data["results"]
    else:
        sys.exit("No results for this search!")
    
    first_output = StringIO()
    first_writer = csv.writer(first_output)

    second_output = StringIO()
    second_writer = csv.writer(second_output)

    output = StringIO()

    first_writer.writerow(data.keys())
    first_writer.writerow(data.values())
    second_writer.writerow(["Results:"])
    for d in second_table:
        second_writer.writerow(d.keys())
        list = []
        for key in d.keys():
            list.append(d[key])
        second_writer.writerow(list)

    first_output.seek(0)
    second_output.seek(0)

    output.write(first_output.read())
    output.write(second_output.read())
    output.seek(0)
    return output.read()

if action.lower() == "ssl":
    request = passivetotal_get(data_loaded["ssl"], query)
    print(to_csv(request))
elif action.lower() == "pdns":
    request = passivetotal_get(data_loaded["pdns"], query)
    print(to_csv(request))
elif action.lower() == "comp":
    request = passivetotal_get(data_loaded["comp"], query)
    print(to_csv(request))
elif action.lower() == "tracker":
    request = passivetotal_get(data_loaded["tracker"], query)
    print(to_csv(request))
elif action.lower() == "malware":
    request = passivetotal_get(data_loaded["malware"], query)
    print(to_csv(request))
elif action.lower() == "whois":
    request = passivetotal_get(data_loaded["whois"], query)
    print(whois_to_csv(request))
elif action.lower() == "subd":
    request = passivetotal_get(data_loaded["subd"], query)
    print(subd_to_csv(request))
else:
    sys.exit("Action is not one of the allowed: ssl, pdns, comp, tracker, malware or whois")



