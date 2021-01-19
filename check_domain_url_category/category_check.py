#!/usr/bin/env python3
# Copyright (c) 2018, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Authors: Scott Shoaf and Anna Barone

import csv
import json
import click
from datetime import datetime
from skilletlib import Panos


# Queries the NGFW to gain Domain Category for given item domain
def query_domain(item, device):
    category = list()
    response = ""
    category_list = ['benign', 'malware', 'command-and-control', 'phishing', 'dynamic-dns', 'newly-registered-domain',
                     'grayware', 'parked', 'proxy-avoidance-anonymizers', 'tbd9', 'tbd10']
    cli_cmd = f'<test><dns-proxy><dns-signature><fqdn>{item}</fqdn></dns-signature></dns-proxy></test>'

    # Query the device object to get the domain category
    try:
        response = device.execute_op(cmd_str=cli_cmd, cmd_xml=False)
    except Exception as e:
        print(f"Error: Problem when executing the op: {e}")
        exit()

    # Parse the response for category
    dns_data = json.loads(response)
    category_num = dns_data['dns-signature'][0]['category']
    dns_category = category_list[category_num]
    print(f'{item}, {dns_category}')

    # Save (domain, category) pairing in output list
    category.append(item)
    category.append(dns_category)

    return category


# Queries the NGFW to gain URL Category and Risk for given item url
def query_url(item, device):
    category = list()
    response = list()

    # Query the device object to get the url test response
    cli_cmd = f'<test><url>{item}</url></test>'
    try:
        response = device.execute_op(cmd_str=cli_cmd, cmd_xml=False).split('\n')
    except Exception as e:
        print(f"Error: Problem when executing the op: {e}")

    # Parse the response for local and cloud classification
    local = response[0]
    cloud = response[1]

    # Parse classification for both local & cloud's category and risk
    category_local, risk_local = local.split(" ")[1], local.split(" ")[2]
    category_cloud, risk_cloud = cloud.split(" ")[1], cloud.split(" ")[2]
    category.append(item)
    category.append(category_cloud)
    category.append('unknown') if risk_cloud == '(Cloud' else category.append(risk_cloud)
    category.append('unknown') if category_local == 'not-resolved' else category.append(category_local)
    category.append('unknown') if risk_local == '(Base' else category.append(risk_local)
    print(f"{category[0]}, {category[1]}, {category[2]}, {category[3]}, {category[4]}")

    # Return the csv output's row
    return category


# Reads in a text file, parses the url/domain, & returns a list of strings
def parse_text_file(infile):
    parsed_list = []
    with open(infile) as f:
        print(f'Reading urls/domains from {infile}.\n')
        for line in f.readlines():
            parsed_list.append(line.rstrip())
    return parsed_list


@click.command()
@click.option("-ip", "--TARGET_IP", help="IP address of the device (localhost)", type=str, default="localhost")
@click.option("-r", "--TARGET_PORT", help="Port to communicate to device (443)", type=int, default=443)
@click.option("-u", "--TARGET_USERNAME", help="Firewall Username (admin)", type=str, default="admin")
@click.option("-p", "--TARGET_PASSWORD", help="Firewall Password (admin)", type=str, default="admin")
@click.option("-t", "--VERIFY_TYPE", help="Type of check, url or domain", type=str, default="domain")
@click.option("-f", "--INPUT_FILE", help="Filename of input list", type=str, default="input_list.txt")
def cli(target_ip, target_port, target_username, target_password, verify_type, input_file):
    # Assert input types are of valid options
    if not (verify_type == "domain" or verify_type == "url"):
        print("Error: Invalid type of verification: (-t) must use either 'domain' or 'url'.")
        exit()

    # Gather domains/urls to parse by reading from text file
    separated_list = parse_text_file(input_file)

    # Creates a firewall object based on skilletlib and pan-python
    print(f"Calling {target_ip} firewall's API to generate an API key.")
    device = Panos(api_username=target_username,
                   api_password=target_password,
                   hostname=target_ip,
                   api_port=target_port)

    file_date = datetime.now().strftime('%Y-%m-%dT%H-%M-%SZ')
    print('\nDomain, category\n----------------\n' if verify_type == 'domain'
          else '\nURL, cloud category, cloud risk, local category, '
               'local risk\n-----------------------------------------------------------\n')

    # Iterate through each domain/url to get category & save to csv
    for item in separated_list:
        category = []
        # Query device object to get the category as a list
        if verify_type == "domain":
            category = query_domain(item, device)
        if verify_type == "url":
            category = query_url(item, device)

        # Write the category list to categories.csv
        with open(f'{verify_type}-category-{file_date}.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(category)

    print('\nURL checks completed.' if verify_type == 'url' else '\nDomain checks completed.')


if __name__ == '__main__':
    cli()
