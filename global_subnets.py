#!/usr/bin/env python3

import prisma_sase
import argparse
from prisma_sase import jd, jd_detailed, jdout
import prismasase_settings
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
import math
import re

# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SCRIPT_NAME = 'CloudGenix: Example script: Domain Global Prefix'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())

try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID

except ImportError:
    PRISMASASE_CLIENT_ID=None
    PRISMASASE_CLIENT_SECRET=None
    PRISMASASE_TSG_ID=None

def global_subnets(cgx, domain, dc_site):    
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
    element_id2n = {}
    route_list = []
    for site in cgx.get.sites().cgx_content['items']:
        if site["element_cluster_role"] == "HUB":
            if dc_site == site["name"]:
                hub_list.append(site["id"])
        if site["element_cluster_role"] == "SPOKE" and site["service_binding"] == domain_id:
            print("Checking site " + site["name"])           
            ############################## check if connected ######################################
            element_list = []
            for elements in cgx.get.elements().cgx_content["items"]:
                if elements["site_id"] == site["id"]:
                    element_list.append(elements["id"])
                    element_id2n[elements["id"]] = elements["name"]
                        
            ############################## Interface status ######################################    
            for element in element_list:
                try:
                    for interface in cgx.get.interfaces(site_id=site['id'], element_id=element).cgx_content["items"]:
                        if interface["scope"] == "global":
                            try:
                                if interface['ipv4_config']:
                                    prefix = ipaddress.ip_network(interface['ipv4_config']['static_config']['address'], strict=False)
                                    if str(prefix) not in global_subnet_list:
                                        global_subnet_list.append(str(prefix))
                                        route_data = {}
                                        route_data["Site_name"] = site["name"]
                                        route_data["Route"] = prefix
                                        route_list.append(route_data)
                            except:
                                print("Unabled to get IPv4 config from interface " + interface["name"])
                except:
                    print("Unabled to get interfaces from " + element_id2n[element])

            ############################## Static Routes ######################################
    
            for element in element_list:
                try:
                    for static in cgx.get.staticroutes(site_id=site['id'], element_id=element).cgx_content["items"]:
                        if static["scope"] == "global":
                            prefix = ipaddress.ip_network(static['destination_prefix'], strict=False)
                            if str(prefix) not in global_subnet_list:
                                global_subnet_list.append(str(prefix))
                                route_data = {}
                                route_data["Site_name"] = site["name"]
                                route_data["Route"] = prefix
                                route_list.append(route_data)
                except:
                    print("Unabled to get static routes from " + element_id2n[element])
                    
                       
            ############################## check BGP status ######################################
            
            try:
                for element in element_list:
                    bgp_list = []
                    bgp_id2n = {}
                    for bgppeers in cgx.get.bgppeers(site_id=site["id"], element_id=element).cgx_content["items"]:
                       if bgppeers["scope"] == "global":
                           bgp_list.append(bgppeers["id"])
                           bgp_id2n[bgppeers["id"]] = bgppeers["name"]
                
                    for bgpstatus in cgx.get.bgppeers_status(site_id=site["id"], element_id=element).cgx_content["items"]:
                        if bgpstatus["id"] in bgp_list:
                            if bgpstatus["state"] == "Established" and bgpstatus["direction"] == "lan":
                                try:
                                    prefixes = cgx.get.bgppeers_reachableprefixes(site_id=site["id"], element_id=element, bgppeer_id=bgpstatus['id']).cgx_content['reachable_ipv4_prefixes']
                                    for prefix in prefixes:
                                        if prefix["network"] not in global_subnet_list:
                                            global_subnet_list.append(prefix["network"])
                                            route_data = {}
                                            route_data["Site_name"] = site["name"]
                                            route_data["Route"] = prefix["network"]
                                            route_list.append(route_data)
                                except:
                                    print("Unabled to get IPv4 prefixes from BGP peer " + bgp_id2n[bgpstatus['id']])
            except:
                print("Failed to check for BGP")
                            
    
    if global_subnet_list:
        print("\nAll Branchs are complete and now creating/updating Routing Prefixes\n")
        prefix_name = domain + "-Global-Subnets"
        
        total_lists = math.ceil(len(global_subnet_list) / 64)
        chunk_size = 60
    
        split_prefix_list = list(split(global_subnet_list, chunk_size))
        
        total_num = 1
        for prefix_list in split_prefix_list:
            new_prefix_name = prefix_name + "-" + str(total_num)
            new_prefix_name = re.sub(r"\s+", "-", new_prefix_name)
            total_num += 1
            num = 1
            new_prefix_list = []
            for prefix in prefix_list:
                new_prefix_list.append({"order":num,"permit":True,"prefix":prefix,"ipv6_prefix":None,"ge":0,"le":0})
                num += 1
            for site in hub_list:
                for elements in cgx.get.elements().cgx_content["items"]:
                    if elements["site_id"] == site:
                        prefix_filter_id = None
                        for prefix_filter in cgx.get.routing_prefixlists(site_id=site, element_id=elements["id"]).cgx_content['items']:
                            if new_prefix_name == prefix_filter['name']:
                                prefix_filter_id = prefix_filter['id']
                                filter_json = prefix_filter
    
                        if prefix_filter_id:
                            filter_json['prefix_filter_list'] = new_prefix_list
                            resp = cgx.put.routing_prefixlists(site_id=site, element_id=elements["id"], routing_prefixlist_id=prefix_filter_id, data=filter_json)
                            if not resp:
                                print (elements["name"] + " Error updating global prefixes " + new_prefix_name)
                                print(str(jdout(resp)))
                            else:
                                print (elements["name"] + " Updating Routing Prefix " + new_prefix_name + " with " + str(len(prefix_list)) + " prefixes from the domain " + domain + " which includes global subnets from interface, static and LAN BGP")
                        else:            
                            new_prefix = {"name":new_prefix_name,"description":domain + "Global Subnets","tags":None,"auto_generated":False,"prefix_filter_list":new_prefix_list}
                            resp = cgx.post.routing_prefixlists(site_id=site, element_id=elements["id"], data=new_prefix)
                            if not resp:
                                print (elements["name"] + " Error creating global prefixes " + new_prefix_name)
                                print(jdout(resp))
                            else:
                                print (elements["name"] + " Creating Routing Prefix " + new_prefix_name + " with " + str(len(prefix_list)) + " prefixes from the domain " + domain + " which includes global subnets from interface, static and LAN BGP")
    
        csv_columns = []        
        for key in (route_list)[0]:
            csv_columns.append(key) 
        csv_file = "routes.csv"
        try:
            with open(csv_file, 'w', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                for data in route_list:
                    try:
                        writer.writerow(data)
                    except:
                        print("Failed to write data for row")
                        print(data)
                print("\nSaved routes.csv file")
        except IOError:
            print("CSV Write Failed")
    else:
        print("No prefixes found to add")
    return    


def split(list_a, chunk_size):

  for i in range(0, len(list_a), chunk_size):
    yield list_a[i:i + chunk_size]
                                          
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    sase_session = prisma_sase.API()
    #sase_session.set_debug(2)
    
    sase_session.interactive.login_secret(client_id=PRISMASASE_CLIENT_ID,
                                          client_secret=PRISMASASE_CLIENT_SECRET,
                                          tsg_id=PRISMASASE_TSG_ID)

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    cgx = sase_session
    print("Domains Found")
    for domain_find in cgx.get.servicebindingmaps().cgx_content['items']:
        print(domain_find["name"])
    
    domain = input ("\nPlease enter the domain you want? ")
    for site in cgx.get.sites().cgx_content['items']:
        if site["element_cluster_role"] == "HUB":
            print(site["name"])
            
    dc_site = input ("\nPlease enter the DC Site you want to create/update these prefixes on? ")
    global_subnets(cgx, domain, dc_site)
    
    # end of script, run logout to clear session.
    return
    
if __name__ == "__main__":
    go()