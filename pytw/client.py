""" PYTW Client module """

import drest
from .exceptions import pytw_error
import constants as Constants
import cve_vuln

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


    def getRecentVulns(self, startDateTime=None):
        """
        :param startDateTime: An optional startDateTime argument to retrieve recent threats. 
                Note only recent threats after startDateTime will be returned if specified.
        :returnValue: Vulns JSON in canonical form
        """

        api_url = Constants.HTTPS_PREFIX + self.__host + Constants.API_BASE_URL
        api = drest.API(api_url)

        # Prepare request parameters
        if (startDateTime == None):
            req_params = {"handle": self.__email, "token": self.__key}
        else:
            req_params = {"handle": self.__email, "token": self.__key, "startdatetime": str(startDateTime)}

        # Call REST API to retrieve recent threats
        response = api.make_request('GET', Constants.RECENT_THREATS_URL, params=req_params)

        if response.status != 200:
            raise pytw_error("REST API call to retrieve recent threats failed")

#        return response.data
        cve_vulns = []
	response_vulns = response.data
        for vuln in response_vulns:
            cve_vulns.append(cve_vuln.CVEVuln(response_vulns[vuln]))

        return cve_vulns

    def __filterVulnsWithUpdatedField(self, threats, threat_field):
        filteredVulns = {}
        for cve in threats:
            for changed_field in threats[cve][Constants.VULN_LAST_CHANGE]:
                if (changed_field == threat_field):
                    filteredVulns[cve] = threats[cve]
                    filteredVulns[cve][Constants.VULN_EXTERNAL_REFERENCES] = []
            for ext_ref in threats[cve][Constants.VULN_EXTERNAL_REFERENCES]:
                for ext_ref_changed_field in ext_ref[Constants.VULN_LAST_CHANGE]:
                    if (ext_ref_changed_field == threat_field):
                        if (filteredVulns.get(cve) == None):
                            filteredVulns[cve] = threats[cve]
                            filteredVulns[cve][Constants.VULN_EXTERNAL_REFERENCES] = []
                        filteredVulns[cve][Constants.VULN_EXTERNAL_REFERENCES].append(ext_ref)

        return filteredVulns

    def filterVulnsWithUpdatedPatches(self, threats):
        """
        :param threats: Vulns JSON in canonical form (typically return value of getRecentVulns() API)
        :returnValue: Filtered threats JSON in canonical form
        """
        filteredVulns = self.__filterVulnsWithUpdatedField(threats, Constants.VULN_PATCHES)
        return filteredVulns


    def filterVulnsWithUpdatedRemediations(self, threats):
        """
        :param threats: Vulns JSON in canonical form (typically return value of getRecentVulns() API)
        :returnValue: Filtered threats JSON in canonical form
        """
        filteredVulns = self.__filterVulnsWithUpdatedField(threats, Constants.VULN_REMEDIATIONS)
        return filteredVulns

    
    def filterVulnsWithUpdatedExploits(self, threats):
        """
        :param threats: Vulns JSON in canonical form (typically return value of getRecentVulns() API)
        :returnValue: Filtered threats JSON in canonical form
        """
        filteredVulns = self.__filterVulnsWithUpdatedField(threats, Constants.VULN_EXPLOITS)
        return filteredVulns

    def getRecentImpacts(self, startTime=None):
        """
        :param startTime: An optional startTime argument to retrieve recent impacts. 
               Note only recent impacts after startTime will be returned if specified
        :returnValue: Impacts JSON in canonical form
        """
        """ TODO """
        raise pytw_error("TO BE IMPLEMENTED")

