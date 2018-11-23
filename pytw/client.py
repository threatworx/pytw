""" PYTW Client module """

import datetime

import drest
from drest import exc

import exceptions
import constants as Constants
import rating
import cve_vuln
import cve_vuln_coll
import impact_status
import impact
import impact_coll
import search_params
import search_filter

class Client(object):
    """ User-created PYTW Client object.

    :param email: Email to identify the user
    :param key: API key to be used
    :param host: Host name to connect to for API calls. Note by default connects to ThreatWatch Cloud SaaS
    """
    
    def __init__(self, email, key, host="api.threatwatch.io"):
        if (host == ""):
            raise exceptions.PyTWError("Invalid argument - 'host'")
        if (email == ""):
            raise exceptions.PyTWError("Invalid argument - 'email'")
        if (key == ""):
            raise exceptions.PyTWError("Invalid argument - 'key'")
        self.__host = host
        self.__email = email
        self.__key = key

    def get_vulns(self, search_params, search_filter):
        """
        :param search_params: An object of type SearchParams
        :param search_filter: An object of type SearchFilter
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        api_url = Constants.HTTPS_PREFIX + self.__host + Constants.URL_FORWARD_SLASH + Constants.API_BASE_URL + Constants.API_VERSION_1
        extra_url_params = {"handle": self.__email, "token": self.__key}
        api = drest.API(api_url, serialize=True, extra_url_params=extra_url_params)

        # Prepare request parameters
        req_params = search_params.to_dict()
        req_params[Constants.SEARCH_FILTERS] = search_filter.to_dict()

        try:

            # Call REST API to retrieve recent threats
            response = api.make_request('POST', Constants.VULNS_URL, params=req_params)

        except exc.dRestRequestError as req_error:
            if (req_error.response.status == 404):
                return cve_vuln_coll.CVEVulnCollection()
            else:
                raise exceptions.PyTWError("REST API call to retrieve vulns failed")
    
        cve_vuln_collection = cve_vuln_coll.CVEVulnCollection()
        response_vulns = response.data
        for vuln in response_vulns:
            cve_vuln_collection.append(cve_vuln.CVEVuln(vuln))

        return cve_vuln_collection

    def get_vulns_by_rating(self, ratings, window_start=None, offset=0, limit=-1):
        """
        :param ratings: A list of ratings (rating.Rating) to filter on.
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        temp_ratings = []
        for r in ratings:
            temp_ratings.append(str(r.value))
        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_RATING, temp_ratings)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_vulns_by_publisher(self, publishers, window_start=None, offset=0, limit=-1):
        """
        :param ratings: A list of publishers to filter on.
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_PUBLISHER, publishers)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_impacting_vulns(self, threshold=None, window_start=None, offset=0, limit=-1):
        """
        :param threshold: An optional threshold to filter on.
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_IMPACTING_VULNS)
        if (threshold is not None):
            search_filter_var.add_filter(Constants.SEARCH_FILTER_THRESHOLD, threshold)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_vulns_by_threshold(self, threshold, window_start=None, offset=0, limit=-1):
        """
        :param threshold: The threshold to filter on.
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_THRESHOLD, threshold)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_vulns_with_exploits(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days with exploits will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_EXPLOITABLE)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_vulns_with_patches(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days with patches will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_PATCH_AVAILABLE)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_vulns_with_remediations(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only vulnerabilities from window_start days with remediations will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_REMEDIATION_AVAILABLE)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_tracked_vulns(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve vulnerabilities
                Only tracked vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_TRACKED_VULNS)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_recent_vulns(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve recent vulnerabilities
                Only recent vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns a CVEVulnCollection object containing CVEVuln instances
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(SEARCH_FILTER_RECENT_DISCOVERED_VULNS)

        return self.get_vulns(search_params_var, search_filter_var)

    def get_impacts(self, search_params, search_filter):
        """
        :param search_params: An object of type SearchParams
        :param search_filter: An object of type SearchFilter
        :Returns an ImpactCollection object containing instances of Impact objects.
        """

        api_url = Constants.HTTPS_PREFIX + self.__host + Constants.URL_FORWARD_SLASH + Constants.API_BASE_URL + Constants.API_VERSION_1
        extra_url_params = {"handle": self.__email, "token": self.__key, "format": "json"}
        api = drest.API(api_url, serialize=True, extra_url_params=extra_url_params)

        # Prepare request parameters
        req_params = search_params.to_dict()
        req_params[Constants.SEARCH_FILTERS] = search_filter.to_dict()

        try:

            # Call REST API to retrieve recent threats
            response = api.make_request('POST', Constants.IMPACTS_URL, params=req_params)

        except exc.dRestRequestError as req_error:
            if (req_error.response.status == 404):
                return impact_coll.VulnImpactCollection()
            else:
                raise exceptions.PyTWError("REST API call to retrieve impacts failed")
    
        impact_collection = impact_coll.ImpactCollection()
        response_impacts = response.data["impacts"]
        for imp in response_impacts:
            impact_collection.append(impact.Impact(imp))

        return impact_collection

    def get_recent_impacts(self, window_start=None, threshold=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve recent impacts
                Only recent impacts from window_start days will be returned if specified.
        :param threshold: An optional threshold, only impacts with confidence greater than threshold will be returned
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects.
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(SEARCH_FILTER_RECENT_IMPACTS)
        if threshold is not None:
           search_filter.var.add_filter(SEARCH_FILTER_THRESHOLD, threshold)

        return self.get_impacts(search_params_var, search_filter_var)

    def get_impacts_by_rating(self, ratings, window_start=None, offset=0, limit=-1):
        """
        :param ratings: A list of ratings (rating.Rating) to filter on.
        :param window_start: An optional number of days argument to retrieve impacts
                Only recent vulnerabilities from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects which meet the criteria.
        """

        temp_ratings = []
        for r in ratings:
            temp_ratings.append(str(r.value))
        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_RATING, temp_ratings)

        return self.get_impacts(search_params_var, search_filter_var)

    def get_impacts_with_exploits(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve impacts
                Only impacts with exploits from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects.
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_EXPLOITABLE)

        return self.get_impacts(search_params_var, search_filter_var)

    def get_impacts_with_patches(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve impacts
                Only impacts with patches from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects which have patches available.
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_PATCH_AVAILABLE)

        return self.get_impacts(search_params_var, search_filter_var)

    def get_impacts_with_remediations(self, window_start=None, offset=0, limit=-1):
        """
        :param window_start: An optional number of days argument to retrieve impacts
                Only impacts with remediations from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects which have patches available.
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_REMEDIATION_AVAILABLE)

        return self.get_impacts(search_params_var, search_filter_var)

    def get_impacts_by_threshold(self, threshold, window_start=None, offset=0, limit=-1):
        """
        :param threshold: Only Impacts with confidence higher than threshold will be returned
        :param window_start: An optional number of days argument to retrieve impacts
                Only impacts with confidence higher than threshold from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects.
        """

        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_THRESHOLD, threshold)

        return self.get_impacts(search_params_var, search_filter_var)

    def get_impacts_by_status(self, statuses, window_start=None, offset=0, limit=-1):
        """
        :param threshold: Only Impacts with specified status values will be returned
        :param window_start: An optional number of days argument to retrieve impacts
                Only impacts with confidence higher than threshold from window_start days will be returned if specified.
        :param offset: An optional offset indicating from where to start in the result set.
        :param limit: An optional limit indicate how many entries from offset to return in the result set.
        :Returns an ImpactCollection object containing instances of Impact objects.
        """
        status_list = []
        for s in statuses:
            status_list.append(s.name)
        search_params_var = search_params.SearchParams(window_start=window_start, offset=offset, limit=limit)
        search_filter_var = search_filter.SearchFilter()
        search_filter_var.add_filter(Constants.SEARCH_FILTER_IMPACT_STATUS, status_list)

        return self.get_impacts(search_params_var, search_filter_var)

