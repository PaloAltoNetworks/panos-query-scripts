# Panos Tools

set of sample skillets for various NGFW config and operations actions
that could be used as part of other use case configurations.

## move rule

Uses the rest API model to move a rule to top, bottom, before or after.

Jinja logic in the skillet so that a second rule name is used for the
before and after options.

## load baseline liab config

This is a simple reset configuration that uses the firewall API to
import and load the xml configuration as a candidate config.

Using python, also shows state capture information such as job ID status.

## content update

This uses the API to update the firewall to the latest content and threat
versions. Useful for new firewall installs or skillets that may require
the latest content update.

Another python skillet using firewall state information and the pan-python
object model.

## brute force exceptions

Set commands to add a set of brute force exceptions to a
named vulnerability security profile.

`NOTE:` the IDs used in this configuration are based on a list from a
support knowledge article. Since IDs can be dynamically added and removed
from the firewall, a commit warning may occur if the IDs are not found
in the local signature database.

https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClmpCAC

The set commands are applied using the CLI while the xml version is designed
for active use of the firewalll API

## connect the firewall to panorama set, xml+rest

This is a simple configuration to both add a Panorama IP address to the firewall
and enable the firewall to install panorama pushed template and device-group
configuration elements.

Setting the IP address is a configuration command while enabling the template
and device-group are operational commands.

The set commands are applied using the CLI for both config and ops.

The xml option is only used for configuration while the REST skillet is
provided for the needed operational enable commands.
