""" Constants for pytw module """

""" Constants for REST API calls """
HTTPS_PREFIX = "https://"
API_BASE_URL = "api/"
API_VERSION_1 = "v1/"
API_VERSION_2 = "v2/"
VULNS_URL = "vulns/"
IMPACTS_URL = "impacts/"
URL_FORWARD_SLASH = "/"

""" Some common fields """
ID = "id"
RATING = "rating"

""" Fields of Vuln Object """
VULN_ID = "id"
VULN_TITLE = "title"
VULN_SUMMARY = "summary"
VULN_VULNERABILITY_TYPES = "vulnerability_types"
VULN_CVSS_VECTOR = "cvss_vector"
VULN_CVSS_SCORE = "cvss_score"
VULN_PUBLISHER = "publisher"
VULN_PUBLISHED_DATETIME = "published"
VULN_LAST_MODIFIED_DATETIME = "last_modified"
VULN_NOTIONAL_LAST_MODIFIED_DATETIME = "notional_last_modified"
VULN_LAST_CHANGE = "last_change"
VULN_PRODUCTS = "products"
VULN_PRODUCT_NAME = "name"
VULN_PRODUCT_VENDOR = "vendor"
VULN_PRODUCT_VERSION = "version"
VULN_EXPLOITS = "exploits"
VULN_EXPLOIT_SOURCE = "source"
VULN_EXPLOIT_URL = "url"
VULN_REMEDIATIONS = "remediations"
VULN_REMEDIATION_SOURCE = "source"
VULN_REMEDIATION_URL = "url"
VULN_REMEDIATION_DESCRIPTION = "description"
VULN_REFERENCES = "references"
VULN_ADVISORIES = "advisories"
VULN_RELATED_VULNS = "related_vulns"
VULN_PATCHES = "patches"
VULN_PATCH_ID = "id"
VULN_PATCH_PRODUCT = "product"
VULN_PATCH_URL = "url"
VULN_PATCH_DESCRIPTION = "description"

""" Fields of VulnImpact object """
IMPACT_VULN_ID = "vuln_id"
IMPACT_ASSET_ID = "asset_id"
IMPACT_PRODUCT = "product"
IMPACT_KEYWORD = "keyword"
IMPACT_CONFIDENCE = "confidence"
IMPACT_STATUS = "status"
IMPACT_TIMESTAMP = "timestamp"
IMPACT_VULNERABILITY = "vulnerability"
