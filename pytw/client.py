""" PYTW Client module """

import drest
import exceptions
import constants as Constants
import cve_vuln
import cve_vuln_coll

import datetime

class Client(object):
    """ User-created PYTW Client object.

    :param email: Email to identify the user
    :param key: API key to be used
    :param host: Host name to connect to for API calls. Note by default connects to ThreatWatch Cloud SaaS
    """
    
    def __init__(self, email, key, host = "api.threatwatch.io"):
        if (host == ""):
            raise pytw_error("Invalid argument - 'host'")
        if (email == ""):
            raise pytw_error("Invalid argument - 'email'")
        if (key == ""):
            raise pytw_error("Invalid argument - 'key'")
        self.__host = host
        self.__email = email
        self.__key = key


    def getRecentVulns(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve recent vulnerabilities
                Only recent vulnerabilities from window_start days will be returned if specified.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        api_url = Constants.HTTPS_PREFIX + self.__host + Constants.URL_FORWARD_SLASH + Constants.API_BASE_URL + Constants.API_VERSION_2
        extra_url_params = {"handle": self.__email, "token": self.__key}
        api = drest.API(api_url, serialize=True, extra_url_params=extra_url_params)


        # Prepare request parameters
        req_params = {}

        if (window_start != None):
            req_params["window_start"] = window_start

        if (offset != None and offset >= 0):
            req_params['offset'] = str(offset)

        if (limit != None and limit >= -1):
            req_params['limit'] = str(limit)

        filters = ['recent-discovered']
        req_params['filters'] = filters

        # Call REST API to retrieve recent threats
        response = api.make_request('POST', Constants.VULNS_URL, params=req_params)

        if response.status != 200:
            raise pytw_error("REST API call to retrieve recent vulns failed")

        cve_vuln_collection = cve_vuln_coll.CVEVulnCollection()
        response_vulns = response.data
        for vuln in response_vulns:
            cve_vuln_collection.append(cve_vuln.CVEVuln(vuln))

        return cve_vuln_collection

    def getRecentImpacts(self, startTime=None):
        """
        :param startTime: An optional startTime argument to retrieve recent impacts. 
               Note only recent impacts after startTime will be returned if specified
        :returnValue: Impacts JSON in canonical form
        """
        """ TODO """
        raise pytw_error("TO BE IMPLEMENTED")

