""" PYTW Client module """

import drest
from .exceptions import pytw_error
import constants as Constants

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
        self.host = host
        self.email = email
        self.key = key


    def getRecentThreats(self, startDateTime=None):
        """
        :param startDateTime: An optional startDateTime argument to retrieve recent threats. 
                Note only recent threats after startDateTime will be returned if specified.
        :returnValue: Threats JSON in canonical form
        """

        api_url = Constants.HTTPS_PREFIX + self.host + Constants.API_BASE_URL
        api = drest.API(api_url)

        # Prepare request parameters
        if (startDateTime == None):
            req_params = {"handle": self.email, "token": self.key}
        else:
            req_params = {"handle": self.email, "token": self.key, "startdatetime": str(startDateTime)}

        # Call REST API to retrieve recent threats
        response = api.make_request('GET', Constants.RECENT_THREATS_URL, params=req_params)

        if response.status != 200:
            raise pytw_error("REST API call to retrieve recent threats failed")

        return response.data

    def filterThreatsWithUpdatedField(self, threats, threat_field):
        filteredThreats = {}
        for cve in threats:
            for changed_field in threats[cve][Constants.THREAT_LAST_CHANGE]:
                if (changed_field == threat_field):
                    filteredThreats[cve] = threats[cve]
                    filteredThreats[cve][Constants.THREAT_EXTERNAL_REFERENCES] = []
            for ext_ref in threats[cve][Constants.THREAT_EXTERNAL_REFERENCES]:
                for ext_ref_changed_field in ext_ref[Constants.THREAT_LAST_CHANGE]:
                    if (ext_ref_changed_field == threat_field):
                        if (filteredThreats.get(cve) == None):
                            filteredThreats[cve] = threats[cve]
                            filteredThreats[cve][Constants.THREAT_EXTERNAL_REFERENCES] = []
                        filteredThreats[cve][Constants.THREAT_EXTERNAL_REFERENCES].append(ext_ref)

        return filteredThreats

    def filterThreatsWithUpdatedPatches(self, threats):
        """
        :param threats: Threats JSON in canonical form (typically return value of getRecentThreats() API)
        :returnValue: Filtered threats JSON in canonical form
        """
        filteredThreats = self.filterThreatsWithUpdatedField(threats, Constants.THREAT_PATCHES)
        return filteredThreats


    def filterThreatsWithUpdatedRemediations(self, threats):
        """
        :param threats: Threats JSON in canonical form (typically return value of getRecentThreats() API)
        :returnValue: Filtered threats JSON in canonical form
        """
        filteredThreats = self.filterThreatsWithUpdatedField(threats, Constants.THREAT_REMEDIATIONS)
        return filteredThreats

    
    def filterThreatsWithUpdatedExploits(self, threats):
        """
        :param threats: Threats JSON in canonical form (typically return value of getRecentThreats() API)
        :returnValue: Filtered threats JSON in canonical form
        """
        filteredThreats = self.filterThreatWithUpdatedField(threats, Constants.THREAT_EXPLOITS)
        return filteredThreats

    def getRecentImpacts(self, startTime=None):
        """
        :param startTime: An optional startTime argument to retrieve recent impacts. 
               Note only recent impacts after startTime will be returned if specified
        :returnValue: Impacts JSON in canonical form
        """
        """ TODO """
        raise pytw_error("TO BE IMPLEMENTED")

