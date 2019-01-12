import re
import os
import subprocess
import argparse
import logging
import requests
import json
from bs4 import BeautifulSoup



def discover_cdh(args):
    prod_list = []
    manifest_url ='https://archive.cloudera.com/cdh5/parcels/'+args.cdh_version+'/manifest.json'
    auth_data = "handle=" + args.handle + "&token=" + args.token + "&format=json"
    asset_id = args.assetid
    if asset_id == None or asset_id == '':
        asset_id = 'cdh-'+args.cdh_version
    url = "https://" + args.instance + "/api/v1"
    asset_url = url + '/assets/' + asset_id
    asset_type = 'Apache Software Foundation'

    manifest_page = requests.get(manifest_url)
    mdict = json.loads(manifest_page.content)
    first_parcel = mdict['parcels'][0]
    if first_parcel is not None:
        for p in first_parcel['components']:
            pkg_name = p['name']
            pkg_version = p['pkg_version'].split('+')[0]
            prod = pkg_name+' '+pkg_version
            prod_list.append(prod)

    artifacts_url='https://www.cloudera.com/documentation/enterprise/release-notes/topics/cdh_vd_cdh5_maven_repo_515x.html'
    apage = requests.get(artifacts_url)
    soup = BeautifulSoup(apage.content, "html5lib")
    dtable = soup.find('table', {'id':'maven_5151__table_bgx_np1_wk'})
    alltrs = dtable.findAll('tr')
    for r in alltrs:
        cols = r.findAll('td')
        if len(cols) == 0:
            continue
        pkgname = cols[2].text.split('_')[0]
        pkgver = cols[3].text.split('-')[0]
        prod = pkgname+' '+pkgver
        prod_list.append(prod)

    resp = requests.get(asset_url + '/type?' + auth_data)
    if resp.status_code != 200:
        # Asset does not exist so create one
        asset_data = "?name=" + asset_id + "&os="+asset_type+"&" + auth_data
        resp = requests.post(asset_url + asset_data)
        if resp.status_code == 200:
            # Asset created successfully, so try to set the type for this asset
            logging.info("Successfully created new asset [%s]", asset_id)
            if (asset_type is not None):
                resp = requests.post(asset_url + '/type/' + asset_type + '?' + auth_data)
                if resp.status_code == 200:
                    logging.info("Successfully set the type [%s] for asset [%s]", asset_type, asset_id)
                else:
                    logging.error("Failed to set type [%s] for asset [%s]", asset_type, asset_id)
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
    products_dict["products"] = prod_list 
    resp = requests.post(asset_url + '/products?' + auth_data, json=products_dict)
    if resp.status_code == 200:
        logging.info("Successfully updated products for asset [%s]", asset_id)
        logging.debug("New products: %s", json.dumps(products_dict["products"]))
    else:
        logging.error("Failed to set products for asset [%s]", asset_id)


logfilename = "cdh_discovery.log"
logging_level = logging.INFO

parser = argparse.ArgumentParser(description='Script to discover Cloudera CDH components as a ThreatWatch asset')
parser.add_argument('--handle', help='The email handle of the user', required=True)
parser.add_argument('--token', help='The API token of the user', required=True)
parser.add_argument('--instance', help='Hostname for your ThreatWatch instance. Defaults to ThreatWatch Cloud SaaS.', default='api.threatwatch.io')
parser.add_argument('--assetid', help='A unique identifier for the CDH asset that will be discovered')
parser.add_argument('--cdh_version', help='', default='5.15.1.4')
args = parser.parse_args()

# Setup the logger
logging.basicConfig(filename=logfilename, level=logging_level, filemode='w', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
console = logging.StreamHandler()
console.setLevel(logging_level)
console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
logging.getLogger('').addHandler(console)

logging.info('Started new run...')
logging.debug('Arguments: %s', str(args))

discover_cdh(args)

logging.info('Run completed...')

