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

# Authors: Scott Shoaf

import click
import json

from skilletlib import Panos

@click.command()
@click.option("-i", "--TARGET_IP", help="IP address of the device (localhost)", type=str, default="localhost")
@click.option("-r", "--TARGET_PORT", help="Port to communicate to device (443)", type=int, default=443)
@click.option("-u", "--TARGET_USERNAME", help="Firewall Username (admin)", type=str, default="admin")
@click.option("-p", "--TARGET_PASSWORD", help="Firewall Password (admin)", type=str, default="admin")
@click.option("-domain", "--domain", help="domain list to query", type=str,
              default="use text file")

def cli(target_ip, target_port, target_username, target_password, domain):
    """
    process a list of domains and get verdict results
    """
    # read in the text file and parse to get domains
    if domain == 'use text file':
        domain_list = []
        with open('domain_list.txt') as f:
            print('\nusing text file input\n')
            for line in f.readlines():
                domain_list.append(line.rstrip())
    else:
        # use the -domain option and a comma separated list of domains
        # useful to spot test a domain without reading the file
        domain_list = domain.split(',')
        print('\n')


    # creates a firewall object based on skilletlib and pan-python
    print('getting firewall API key\n')
    device = Panos(api_username=target_username,
                   api_password=target_password,
                   hostname=target_ip,
                   api_port=target_port
                   )

    print('Domain, category')
    print('----------------\n')

    # responses give a category code value
    # TODO: get the complete list
    category_list = ['benign', 'malware', 'command-and-control']


    for item in domain_list:
        # query the device object to get the domain category
        cli_cmd = f'<test><dns-proxy><dns-signature><fqdn>{item}</fqdn></dns-signature></dns-proxy></test>'
        response = device.execute_op(cmd_str=cli_cmd, cmd_xml=False)
        dns_data = json.loads(response)
        category_num = dns_data['dns-signature'][0]['category']
        dns_category = category_list[category_num]
        print(f'{item}, {dns_category}')

    print('\nDomain checks complete')


if __name__ == '__main__':
    cli()