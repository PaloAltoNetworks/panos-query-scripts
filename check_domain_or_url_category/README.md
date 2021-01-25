# Domain and URL Category Check

This solution uses a 10.0 or later NGFW API to test a set of either domains/FQDNs or URLs and returns their
 categories. 

For reference, here is a current, complete [domain category list](https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/threat-prevention/dns-security/dns-security-analytics.html)
and a current, complete [URL filtering category list](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm5hCAC).

### Running the Script

```python
python category_check.py {parameters}
```

Input parameters:

* -ip = IP address of the NGFW (default=localhost)
* -r = TCP port to access the device (default=443)
* -u = NGFW username (default=admin)
* -p = NGFW password (default=admin)
* -t = type of category check, either 'domain' or 'url' (default=domain)  
* -f = input text file of urls/domains to test (absolute or relative path)

Running the script will:

* generate and get the API from the NGFW
* query the NGFW to get the category for each input domain/url
* output the domain/url and category on screen and in domain-category-{date}-{time}.csv or url-category-{date}-{time}.csv

Also, this solution can be run in [Panhandler](https://live.paloaltonetworks.com/t5/skillet-tools/install-and-get-started-with-panhandler/ta-p/307916)
by importing this repository into your instance of Panhandler and playing the python3 skillet called *query NGFW API to get url/domain category*.
The automation will ask for the input parameters through the Panhandler user interface, generate its own virtual environment, 
run the *category_check.py* script, and output the categorizations to the screen. 


### Known and Potential Issues

The DNS query may encounter a 'Server Busy' response that is not covered in the
code. Update TBD

New domain categories added before code updates will result in an output error due to
an unknown category value. The goal is to keep the code current as new 
categories are released. To keep this code update, add the new domain category name
to the list variable named `category_list`(inside `category_check.py`) with the index 
in the list correlating to the category number returned from the firewall test call.

### Python Dependencies

* click: used for input parameter capture
* skilletlib: library used to interact with the NGFW API
