# Domain Category Check

use a 10.0 or later NGFW API to check a set of domains/FQDNs and return their
 category

[Current category list](https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-new-features/content-inspection-features/dns-security-signature-categories.html#:~:text=DNS%20Security%20Categories%20allows%20you,for%20a%20given%20signature%20source.)


```python
python domain_check.py {parameters}
```

Input parameters:

* -ip = ip address of the NGFW
* -r = tcp port to access the device (default=443)
* -u = NGFW username (default=admin)
* -p = NGFW password (default=admin)
* -d = input domain (omit to use an input list)

> The current version uses a static list file name of domain_list.txt to be
> found in the same directory as the python file

Running the script will:

* generate and get the API from the NGFW
* query the NGFW to get the category for each input domain
* output the domain and category on screen and in domains_and_categories.csv


Known and Potential Issues

The DNS query may encounter a 'Server Busy' response that is not covered in the
code. Update TBD

New categories added before code updates will result in an output error due to
an unknown category value. The goal is to keep the code current as new 
categories are released

Python Dependencies

* click: used for input parameter capture
* skilletlib: library used to interact with the NGFW API

