import pytw
# Replace handle and token 
pytw_client = pytw.client.Client("handle","token",'api.threatwatch.io')
sp = pytw.search_params.SearchParams(window_start=365,limit=10)
impacts_filter = sp.add_asset_with_open_impacts_filter()
#print(impacts_filter)

rating_list = [pytw.rating.Rating(1),pytw.rating.Rating(2),pytw.rating.Rating(3),pytw.rating.Rating(4),pytw.rating.Rating(5)]
rating_filter = sp.add_ratings_filter(rating_list)
#print(rating_filter)
#Asset Module
sp.add_exploitable_filter()
#asset_list = ["psktw"]
#create_asset = pytw_client.create_asset(asset_list)
#print(create_asset) 

print("\nAssets:")
all_assets = pytw_client.get_assets(sp)
sp.add_asset_patch_filter("openexr-2.4.1-r3.apk")
for a in all_assets:
    print("Asset id: %s"% a.get_id()) #The ID of Asset
    print("Asset name: %s" % a.get_asset_name()) #The Assets name
    print("Asset description:[%s]" %  a.get_description()) #The Assets Descriptiion
    print("Asset Owner:%s" % a.get_owner()) #The Asset Owner
    print("Asset Location: %s"%a.get_location()) #The location of Asset
    print("Asset notifications:%s"%a.get_notify())
    #print("Asset products:%s"% a.get_products()) 
    patches_list = a.get_patches()
    print("Asset patches:%s" % patches_list) #The Asset Patches
    for p in patches_list :
        print("Patch id is %s"% p)        
    print("Asset Tags:%s" % a.get_tags()) #The Asset Tags
    print("Asset types:%s" % a.get_type())
    print("Updated:%s"% a.is_updated())
    ajson = a.to_json()
    #print(ajson)

asset2= pytw_client.get_asset_by_id("Windows2016DC")
print("ASSET Details:",asset2)
"""for a2 in asset2:
    a2.set_description("The asset is a laptop with a small RAM & has some bugs")
    a2.set_owner("pushkar@threatwatch.io")
    a2.set_location("f:/local/temp")
"""
asset2.set_description("The asset is a laptop with a small RAM & has some bugs")

upd_asset = pytw_client.update_asset(asset2)
print("Updated or not:",upd_asset)
print("ASSET Details:",asset2)
#assetidup= all_assets.to_json()
#is_assetupdated = pytw_client.update_asset(assetidup)
#print(is_assetupdated)

for a1 in all_assets:
    print("\n\n")
    a1.set_asset_name("pskokil18")
    a1.set_description("The asset is an old computer with some issues of speed,memory")
    a1.set_owner("pushkar@threatwatch.io")
    a1.set_location("f:/local/temp")
    #a1.set_notify("")
    a1.set_patches("{'id':'KB4532947'}, {'id': 'KB4549947'}, {'id': 'KB4549949'}")
    plist = [{"version": ">=fw940.00 <fw940.20", "vendor": "ibm", "name": "power9 system firmware"}, {"version": ">=fw930.00 <fw930.30", "vendor": "ibm", "name": "power9 system firmware firmware"}, {"version": "<fw950.00", "vendor": "ibm", "name": "power9 system firmware"}, {"version": "<op940.20", "vendor": "ibm", "name": "scale-out lc system firmware"}]
    a1.set_products(plist)
    tlist = ['OS_RELEASE:Ubuntu 18.04 LTS', 'Linux', 'Ubuntu', 'SSH Audit', 'Host Benchmark']
    a1.set_tags(tlist)
    a1.set_type("Windows 7")
    print("Asset id: %s"% a1.get_id()) #The ID of Asset
    print("Asset name: %s" % a1.get_asset_name()) #The Assets name
    print("Asset description:[%s]" %  a1.get_description()) #The Assets Descriptiion
    print("Asset Owner:%s" % a1.get_owner()) #The Asset Owner
    print("Asset Location: %s"%a1.get_location()) #The location of Asset
    print("Asset products:%s"% a1.get_products()) 
    patches_list = a1.get_patches()
    print("Asset patches:%s" % patches_list) #The Asset Patches
    print("Asset Tags:%s" % a1.get_tags()) #The Asset Tags
    print("Asset types:%s" % a.get_type())

#Impact Module
print("\nImpacts:")
sp = pytw.search_params.SearchParams(window_start=365,limit=10)
#impacts_filter = sp.add_asset_with_open_impacts_filter()
#sp.add_free_text_search_filter("1182104d1089460dbcc0c94ff1954c8c")
sp.add_threshold_filter(100)
all_impacts = pytw_client.get_impacts(sp)
for i in all_impacts:
    #Vulnerability id,products,asset id
    print("Vuln ID [%s] affected Product [%s] on Asset ID [%s]" % (i.get_vuln_id(),i.get_vulnerable_product(),i.get_asset_id()))
    print("Rating: %s"%i.get_rating_as_str()) #Rating of vulnerability in string
    print("Rating as Integer:%s"%i.get_rating_as_int())
    print("Rating as String:%s"%i.get_rating_as_str())
    print("timestamp:%s"%i.get_timestamp()) #Timestamp of Impact
    print("Confidence:%s"%i.get_confidence()) #Impact Confidence
    print("Status:%s"%i.get_status()) #Impact status

    #print("Vulnaribility %s"%i.get_vulnerability())
count = 0

asset_idL = ['Windows2016DC']
asset_impacts = pytw_client.get_impacts_by_asset_ids(asset_idL)
print(asset_impacts)

while True:
    sp.set_offset(count)
    temp_impacts = pytw_client.get_impacts(sp)
    temp_count = len(temp_impacts)
    #print("Temp count: %s" % temp_count)
    if temp_count == 0:
        break
    count = count + temp_count

#Count of Impacts
print("\nCount of impacts: %s" % count)

print("\nCount of impacts with priority 4 & 5:")
ratings = [ pytw.rating.Rating(4), pytw.rating.Rating(5) ]
print(ratings)

filtered_impacts = pytw_client.get_impacts_by_rating(ratings)
print(len(filtered_impacts))


#Vulnerabilities module with product & patches submodules
print("\nVulnerabilities:")
sp = pytw.search_params.SearchParams(window_start=30,limit=100)
sp.add_patch_available_filter()
vulns = pytw_client.get_vulns(sp)
#sp.add_patch_available_filter()
for v in vulns:
    #Vulnerability id & title
    print("Vuln ID [%s] - [%s]" % (v.get_id(),v.get_title()))
    print("Is it new?%s"%v.is_new())
    print("CVSS Score:%s" % v.get_cvss_score()) # CVV Score of Vulnerability
    print("CVSS Vector:%s" % v.get_cvss_vector())
    prod_list = v.get_products()
    #print("Products list:",prod_list)
    #print("Products: %s" % v.get_products())
    print("Products:")
    if prod_list is not None:
        for p in prod_list:
            print("Product name:%s"% p.get_name())#Product name
            print("Product vendor is %s" % p.get_vendor()) #Product vendor
            print("Product version is %s"% p.get_version()) #Product Version
    print("Exploits:")
    exploit_list = v.get_exploits()
    for e in exploit_list:
        print("Exploit Source:%s" % e.get_source())
        print("Exploit URL:%s" % e.get_url())
    patches_list = v.get_patches()
    #print("Patches: %s" % patches_list)
    for p in patches_list:
        print("Patch Id:%s" % p.get_id()) #Patch id
        print("Product:%s" % p.get_product())
        print("Patch URL:%s" % p.get_url())

for i in all_impacts: 
    print("Vuln ID [%s] affected Product [%s] on Asset ID [%s]" % (i.get_vuln_id(),i.get_vulnerable_product(),i.get_asset_id()))

count = 0
while True:
    sp.set_offset(count)
    temp_impacts = pytw_client.get_impacts(sp)
    temp_count = len(temp_impacts)
    if temp_count == 0:
        break
    count = count + temp_count
print ("Count of impacts: %s" % count)

print("Count of impacts with priority 4 & 5:")
ratings = [ pytw.rating.Rating(4), pytw.rating.Rating(5) ] 
print(ratings)

filtered_impacts = pytw_client.get_impacts_by_rating(ratings)
print(len(filtered_impacts))

#Vulnerability module with submodule Remediations
print("\nVulnerabilities:")
vulns = pytw_client.get_vulns(sp)
for v in vulns:
    #Vulnerability id with title
    print ("Vuln ID [%s] - [%s]" % (v.get_id(),v.get_title()))
    print("Published Date:%s"% v.get_published_datetime()) #Published date of Vulnerability
    print("References:%s"% v.get_references()) #References for Vulnerability
    print("Summary:%s"% v.get_summary()) #Summary of Vulnerability
    print("Vulnerability types:%s"%v.get_vuln_types()) #Types of Vulnerabilities
    print("Modified date:%s"% v.get_notional_last_modified_datetime())
    remediation_list = v.get_remediations() 
    #print(remediation_list)   
    if remediation_list is not None:
        for r in remediation_list:
            print("Remediation description:%s"%r.get_description())#Remediation description
            print("Remediation URL:%s"%r.get_url()) #Remediation URL

