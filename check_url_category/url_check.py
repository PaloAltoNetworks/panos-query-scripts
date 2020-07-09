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
from skilletlib import Panos

@click.command()
@click.option("-i", "--TARGET_IP", help="IP address of the device (localhost)", type=str, default="localhost")
@click.option("-r", "--TARGET_PORT", help="Port to communicate to device (443)", type=int, default=443)
@click.option("-u", "--TARGET_USERNAME", help="Firewall Username (admin)", type=str, default="admin")
@click.option("-p", "--TARGET_PASSWORD", help="Firewall Password (admin)", type=str, default="admin")
@click.option("-url", "--url", help="url list to ping", type=str,
              default="use text file")

def cli(target_ip, target_port, target_username, target_password, url):
    """
    process a list of URLs and get ping results
    """

    if url == 'use text file':
        url_list = []
        with open('url_list.txt') as f:
            print('\nusing text file input\n')
            for line in f.readlines():
                url_list.append(line.rstrip())
    else:
        url_list = url.split(',')
        print('\n')


    print('getting firewall API key\n')
    device = Panos(api_username=target_username,
                   api_password=target_password,
                   hostname=target_ip,
                   api_port=target_port
                   )
    print('URL, local category, local risk, cloud category, cloud risk')
    for item in url_list:
        # query the device object to get the url category
        #cli_cmd = f'test url {item}'
        cli_cmd = f'<test><url>{item}</url></test>'
        response = device.execute_op(cmd_str=cli_cmd, cmd_xml=False).split('\n')
        local = response[0]
        cloud = response[1]
        #print(response)
        categoryLocal, riskLocal = local.split(" ")[1], local.split(" ")[2]
        categoryCloud, riskCloud = cloud.split(" ")[1], cloud.split(" ")[2]
        if categoryLocal == 'not-resolved':
            print(f'{item}, {categoryLocal}, unknown, {categoryCloud}, {riskCloud}')
        else:
            print(f'{item}, {categoryLocal}, {riskLocal}, {categoryCloud}, {riskCloud}')

    print('\nURL checks complete')
if __name__ == '__main__':
    cli()