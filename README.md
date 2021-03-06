# PAN-OS Query Scripts and Skillets

This solution is a set of basic utilities to pull info from the Next Generation 
Firewall (NGFW) or use the NGFW to get cloud-based information, such as URL categories
or DNS domain verdicts.

The basic utilities include: 

    * A solution that checks a set of either domains or URLs categories
    * A solution that queries a NGFW to determine which rules allow traffic from an untrusted zone on the firewall


> These solutions can be run as Python files or as skillets, using Panhandler. For help with Panhandler set-up and
> use, please reference the 
> [Quickstart Guide](https://live.paloaltonetworks.com/t5/skillet-tools/install-and-get-started-with-panhandler/ta-p/307916) 
> in the Live community. 

## Support Policy
The code and templates in the repo are released under an as-is, best effort,
support policy. These scripts should be seen as community supported and
Palo Alto Networks will contribute our expertise as and when possible.
We do not provide technical support or help in using or troubleshooting the
components of the project through our normal support options such as
Palo Alto Networks support teams, or ASC (Authorized Support Centers)
partners and backline support options. The underlying product used
(the VM-Series firewall) by the scripts or templates are still supported,
but the support is only for the product functionality and not for help in
deploying or using the template or script itself. Unless explicitly tagged,
all projects or work posted in our GitHub repository
(at https://github.com/PaloAltoNetworks) or sites other than our official
Downloads page on https://support.paloaltonetworks.com are provided under
the best effort policy.
