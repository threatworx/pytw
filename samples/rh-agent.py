import re
import platform
import os
import subprocess
import argparse
import logging
import requests
import json

import pytw.client as pytw_client
import pytw.search_params as search_params

def get_asset_type():
    os_type = platform.dist()[0]
    if "centos" in os_type:
        return "CentOS"
    elif "redhat" in os_type:
        return "Red Hat"
    elif "Ubuntu" in os_type:
        return "Ubuntu"
    else:
        return "Other" 

def discover_rh():
    plist = []
    cmdarr = ["/usr/bin/yum", "list", "installed"]
    logging.info("Retrieving product details from host")
    yumout = subprocess.check_output(cmdarr)
    for l in yumout.splitlines():
        if 'Installed Packages' in l:
            continue
        lsplit = l.split()
        pkg = lsplit[0]
        if len(lsplit) > 1:
            ver = lsplit[1]
        else:
            ver = ''
        pkg = pkg.replace('.noarch','')
        pkg = pkg.replace('.i686','')
        pkg = pkg.replace('.x86_64','')
        ver = ver.replace('_','-')
        if ':' in ver:
            ver = ver.split(':')[1]
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details from host")
    return plist

def discover_ubuntu():
    plist = []
    cmdarr = ["/usr/bin/apt", "list", "--installed"]
    logging.info("Retrieving product details from host")
    yumout = subprocess.check_output(cmdarr)
    for l in yumout.splitlines():
        if 'Listing...' in l:
            continue
        lsplit = l.split()
        pkg = lsplit[0].split('/')[0]
        ver = lsplit[1]
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details from host")
    return plist

def discover(args):
    handle = args.handle
    token = args.token
    instance = args.instance
    downloadonly = args.downloadonly
    download_directory =  args.downloaddir
    asset_id = args.assetid
    url = "https://" + instance + "/api/v1"
    asset_url = url + '/assets/' + asset_id
    auth_data = "handle=" + handle + "&token=" + token + "&format=json"

    atype = get_asset_type()
    print atype

    if atype == 'Red Hat' or atype == 'CentOS':
        plist = discover_rh()
    elif atype == 'Ubuntu':
        plist = discover_ubuntu()
    print plist

    if downloadonly == True:
        filepath = download_directory
        if download_directory.endswith('/') == False:
            filepath = filepath + '/asset-products.csv'
        else:
            filepath = filepath + 'asset-products.csv'
        logging.info("Creating CSV file [%s]", filepath)
        csv = open(filepath, "w")
        for p in plist:
            csv.write(p + ',')
            logging.debug("Wrote product [%s] to CSV file", p)
        csv.close()
        logging.info("Successfully wrote CSV file [%s]", filepath)
        return

    resp = requests.get(asset_url + '/type?' + auth_data)
    if resp.status_code != 200:
        # Asset does not exist so create one
        asset_data = "?name=" + asset_id + "&os=" + atype + "&" + auth_data
        resp = requests.post(asset_url + asset_data)
        if resp.status_code == 200:
            # Asset created successfully, so try to set the type for this asset
            logging.info("Successfully created new asset [%s]", asset_id)
            asset_type = get_asset_type()
            if (asset_type is not None):
                resp = requests.post(asset_url + '/type/' + asset_type + '?' + auth_data)
                if resp.status_code == 200:
                    logging.info("Successfully set the type ["+atype+"] for asset [%s]", asset_id)
                else:
                    logging.error("Failed to set type ["+atype+"] for asset [%s]", asset_id)
                    logging.error("Response details: %s", resp.content)
            else:
                logging.error("Unable to detect type of asset...")
                logging.error("Not setting asset type...")
        else:
            logging.error("Failed to create new asset [%s]", asset_id)
            logging.error("Response details: %s", resp.content)
            return
    else:
        # Delete existing products for the asset
        logging.info("Atempting to remove existing products for asset [%s]", asset_id)
        resp = requests.delete(asset_url + "/products?" + auth_data)
        if resp.status_code == 200:
            logging.info("Removed existing products for asset [%s]", asset_id)
        else:
            logging.error("Failed to remove existing products for asset [%s]", asset_id)

    # Set the products for the asset
    logging.info("Atempting to set products for asset [%s]", asset_id)
    products_dict = {}
    products_dict["products"] = plist
    resp = requests.post(asset_url + '/products?' + auth_data, json=products_dict)
    if resp.status_code == 200:
        logging.info("Successfully updated products for asset [%s]", asset_id)
        logging.debug("New products: %s", json.dumps(products_dict["products"]))
    else:
        logging.error("Failed to set products for asset [%s]", asset_id)


def patch(args):
    email_handle = args.handle
    api_token = args.token
    tw_instance = args.instance
    downloadonly = args.downloadonly
    download_directory =  args.downloaddir
    window_start = args.windowstart
    asset_ids = []
    asset_ids.append(args.assetid)
    publishers = []
    publishers.append("CentOS")

    yum_command = "yum install "
    yum_download_cmd_args = "--downloadonly --downloaddir="
    no_output = " 1&>2 /dev/null"
    asset_patches_set = set()

    client = pytw_client.Client(email_handle, api_token, tw_instance)
    sp = search_params.SearchParams(window_start=window_start)
    sp.add_patch_available_filter()
    sp.add_publishers_filter(publishers)
    sp.add_asset_ids_filter(asset_ids)
    logging.info('Getting impacts from ThreatWatch')
    impacts = client.get_impacts(sp) 
    logging.info('Retrieved %s impacts', str(len(impacts)))

    if (len(impacts) == 0):
        logging.info('No impacts found for asset [%s]', asset_ids[0])
        return

    logging.info('Processing impacts')
    for i in impacts:
        logging.debug('Impact details: %s', str(i))
        patches = i.get_vulnerability().get_patches()
        for p in patches:
            patch_id = p.get_id()
            patch_name = re.findall(r'(([a-zA-Z0-9]+\-)+)[0-9]+\.', patch_id)
            asset_patches_set.add(patch_name[0][0][:-1])

    if (len(asset_patches_set) == 0):
        logging.info("No patches found for asset [%s]", asset_ids[0])
        return

    operation = "install"
    if downloadonly == True:
        yum_command = yum_command + yum_download_cmd_args + download_directory
        operation = "download"

    logging.info("Asset: %s", asset_ids[0])
    logging.info("Number of patches found: %s", str(len(asset_patches_set)))
    logging.info("Patches found: %s", str(asset_patches_set))
    for p in asset_patches_set:
        temp_yum_command = yum_command + " " + p + no_output
        logging.info('Running command [%s]', temp_yum_command)
        yum_cmd_exit_code = os.system(temp_yum_command)
        if (yum_cmd_exit_code != 0):
            logging.info("Patch [%s] %s failed", p, operation)
        else:
            logging.info("Patch [%s] %s succeeded", p, operation)

# Entry code
logfilename = "rh-agent.log"
logging_level = logging.INFO

parser = argparse.ArgumentParser(description='RedHat-Agent helps discover and patch assets of RedHat family')
parser.add_argument('--handle', help='Specify the email handle of the user', required=True)
parser.add_argument('--token', help='Specify the API token of the user', required=True)
parser.add_argument('--instance', help='Specify the ThreatWatch instance. Defaults to ThreatWatch Cloud SaaS.', default='api.threatwatch.io')
parser.add_argument('--mode', help='Specify the mode [discover|patch] of operation. "discover" - Discover products for given asset. "patch" - Patching operation for given asset.', required=True, choices=['discover','patch'])
parser.add_argument('--assetid', help='Specify the ID of the asset for which to perform specified operation', required=True)
parser.add_argument('--downloadonly', help='For [discover] operation - only download CSV (asset-products.csv) of discovered asset. For [patch] operation - only download patches, do not install these.', action='store_true', default=False)
parser.add_argument('--downloaddir', help='Specify the staging directory where to download CSV or patches', default='.')
parser.add_argument('--windowstart', help='Specify number of last days from which to get impacts for patching', default=7, type=int)
args = parser.parse_args()

# Setup the logger
logging.basicConfig(filename=logfilename, level=logging_level, filemode='w', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
console = logging.StreamHandler()
console.setLevel(logging_level)
console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
logging.getLogger('').addHandler(console)

logging.info('Started new run...')
logging.debug('Arguments: %s', str(args))

if get_asset_type() == "Other":
    logging.info('Not a supported platform')
    sys.exit(1)
if args.mode == "discover":
    discover(args)
if args.mode == "patch":
    patch(args)

logging.info('Run completed...')

