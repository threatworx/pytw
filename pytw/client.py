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


    def getRecentVulns(self, duration=None):
        """
        :param duration: An optional number of days argument to retrieve recent threats. 
                Only recent threats from last 'duration' days will be returned if specified.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        api_url = Constants.HTTPS_PREFIX + self.__host + Constants.URL_FORWARD_SLASH + Constants.API_BASE_URL + Constants.API_VERSION_1
        api = drest.API(api_url)


        # Prepare request parameters
        if (duration == None):
            req_params = {"handle": self.__email, "token": self.__key}
        else:
            today  = datetime.datetime.today()
            startDateTime = today - datetime.timedelta(days=int(duration))
            req_params = {"handle": self.__email, "token": self.__key, "startdatetime": str(startDateTime)}

        # Call REST API to retrieve recent threats
        response = api.make_request('GET', Constants.RECENT_VULNS_URL, params=req_params)

        if response.status != 200:
            raise pytw_error("REST API call to retrieve recent threats failed")

        cve_vuln_collection = cve_vuln_coll.CVEVulnCollection()
        response_vulns = response.data
        for vuln in response_vulns:
            cve_vuln_collection.append(cve_vuln.CVEVuln(response_vulns[vuln]))

        return cve_vuln_collection

    def getRecentImpacts(self, startTime=None):
        """
        :param startTime: An optional startTime argument to retrieve recent impacts. 
               Note only recent impacts after startTime will be returned if specified
        :returnValue: Impacts JSON in canonical form
        """
        """ TODO """
        raise pytw_error("TO BE IMPLEMENTED")

