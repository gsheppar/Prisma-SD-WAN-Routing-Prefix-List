#!/usr/bin/env python3

# 20201020 - Add a function to add a single prefix to a local prefixlist - Dan
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed
import cloudgenix_settings
import sys
import logging
import os
import datetime
import collections
import csv
import ipaddress
from csv import DictReader
import time
from datetime import datetime, timedelta
jdout = cloudgenix.jdout


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Domain Global Prefix'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

def global_subnets(cgx, domain, add):    
    domain_id = None
    for domain_find in cgx.get.servicebindingmaps().cgx_content['items']:
        if domain == domain_find["name"]:
            domain_id = domain_find["id"]
    
    if not domain_id:
        print("Can't find domain " + domain)
        return
    
    global_subnet_list = []
    hub_list = []
    site_id2n = {}
    for site in cgx.get.sites().cgx_content['items']:
        if site["element_cluster_role"] == "HUB":
            hub_list.append(site["id"])
        if site["element_cluster_role"] == "SPOKE" and site["service_binding"] == domain_id:
            print("Checking site " + site["name"])           
            ############################## check if connected ######################################
            element_list = []
            for elements in cgx.get.elements().cgx_content["items"]:
                if elements["site_id"] == site["id"]:
                    element_list.append(elements["id"])
                        
            ############################## Interface status ######################################
    
            for element in element_list:
                for interface in cgx.get.interfaces(site_id=site['id'], element_id=element).cgx_content["items"]:
                    if interface["scope"] == "global":
                        try:
                            if interface['ipv4_config']:
                                prefix = ipaddress.ip_network(interface['ipv4_config']['static_config']['address'], strict=False)
                                if prefix not in global_subnet_list:
                                    global_subnet_list.append(str(prefix))
                        except:
                            print("Unabled to get IPv4 config from interface " + interface["name"])

            ############################## Static Routes ######################################
    
            for element in element_list:
                for static in cgx.get.staticroutes(site_id=site['id'], element_id=element).cgx_content["items"]:
                    if static["scope"] == "global":
                        prefix = ipaddress.ip_network(static['destination_prefix'], strict=False)
                        if prefix not in global_subnet_list:
                            global_subnet_list.append(str(prefix))
                       
            ############################## check BGP status ######################################
            
            bgp_id2n = {}
            for bgp in cgx.get.bgppeers(site_id=site['id'], element_id=element).cgx_content["items"]:
                bgp_id2n[bgp["id"]] = bgp["name"]
            for element in element_list:
                for bgpstatus in cgx.get.bgppeers_status(site_id=site["id"], element_id=element).cgx_content["items"]:
                    if bgpstatus["state"] == "Established" and bgpstatus["direction"] == "lan":
                        try:
                            prefixes = cgx.get.bgppeers_reachableprefixes(site_id=site["id"], element_id=element, bgppeer_id=bgpstatus['id']).cgx_content['reachable_ipv4_prefixes']
                            for prefix in prefixes:
                                if prefix["network"] not in global_subnet_list:
                                    global_subnet_list.append(prefix["network"])
                        except:
                            print("Unabled to get IPv4 prefixes from BGP peer " + bgp_id2n[bgpstatus['id']])
    
    if global_subnet_list:
        print("\nAll Branchs are complete and now creating/updating Routing Prefixes\n")
        prefix_name = domain + "-Global-Subnets"
        new_prefix_list = []
        num = 1
        for prefix in global_subnet_list:
            new_prefix_list.append({"order":num,"permit":True,"prefix":prefix,"ge":0,"le":0})
            num += 1
        for site in hub_list:
            for elements in cgx.get.elements().cgx_content["items"]:
                if elements["site_id"] == site:
                    prefix_filter_id = None
                    for prefix_filter in cgx.get.routing_prefixlists(site_id=site, element_id=elements["id"]).cgx_content['items']:
                        if prefix_name == prefix_filter['name']:
                            prefix_filter_id = prefix_filter['id']
                            filter_json = prefix_filter
        
                    if prefix_filter_id:
                        if add:
                            add_list = []
                            for prefix in global_subnet_list:
                                exsists = False
                                for current_prefix in filter_json['prefix_filter_list']:
                                    if current_prefix['prefix'] == prefix:
                                        exsists = True
                                        break
                                if not exsists:
                                    add_list.append(prefix)
                            num = len(filter_json['prefix_filter_list'])
                            if add_list:
                                for prefix in add_list:
                                    num += 1
                                    filter_json['prefix_filter_list'].append({"order":num,"permit":True,"prefix":prefix,"ge":0,"le":0})
                                resp = cgx.put.routing_prefixlists(site_id=site, element_id=elements["id"], routing_prefixlist_id=prefix_filter_id, data=filter_json)
                                if not resp:
                                    print (elements["name"] + " Error updating global prefixes " + prefix_name)
                                else:
                                    print (elements["name"] + " Updating Routing Prefix" + " with the addtion of " + str(len(add_list)) + " prefixes from the domain " + domain + " global subnets from interface, static and LAN BGP")
                            else:
                                print (elements["name"] + " No new prefixes to add to Routing Prefix " + prefix_name)
                            
                                    
                        else:
                            filter_json['prefix_filter_list'] = new_prefix_list
                            resp = cgx.put.routing_prefixlists(site_id=site, element_id=elements["id"], routing_prefixlist_id=prefix_filter_id, data=filter_json)
                            if not resp:
                                print (elements["name"] + " Error updating global prefixes " + prefix_name)
                            else:
                                print (elements["name"] + " Updating Routing Prefix " + prefix_name + " with " + str(len(global_subnet_list)) + " prefixes from the domain " + domain + " which includes global subnets from interface, static and LAN BGP")
                            
                            
        
                    else:            
                        new_prefix = {"name":prefix_name,"description":domain + "Global Subnets","tags":None,"auto_generated":False,"prefix_filter_list":new_prefix_list}
                        resp = cgx.post.routing_prefixlists(site_id=site, element_id=elements["id"], data=new_prefix)
                        if not resp:
                            print (elements["name"] + " Error creating global prefixes " + prefix_name)
                            print(jdout(resp))
                        else:
                            print (elements["name"] + " Creating Routing Prefix " + prefix_name + " with " + str(len(global_subnet_list)) + " prefixes from the domain " + domain + " which includes global subnets from interface, static and LAN BGP")

        
    return    

                                          
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
    config_group.add_argument('--add', '-A', help='Add only', action='store_true', default=False)
    
    args = vars(parser.parse_args())
                             
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    add = args['add']
    domain = input ("Please enter the domain you want? ")
    global_subnets(cgx, domain, add)
    
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()