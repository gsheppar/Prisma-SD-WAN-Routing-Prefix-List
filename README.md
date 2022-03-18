# Prisma SD-WAN Routing Prefix List (Preview)
The purpose of this script is from a domain grab all the global prefixes (Interface, Static, LAN BGP) and create a Prefix List in each DC ION

#### Features
 - ./global_subnets.py can be used to look at a domain and grab all the global prefixes (Interface, Static, LAN BGP) and create a Prefix List in each DC 
 
#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 - Use the global_subnets.py which will ask for a domain
 1. ./global_subnets.py
      - Will create a global prefix list in each DC ION based off the domain name you give with all the global prefixes (Interface, Static, LAN BGP)
 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan.html>
