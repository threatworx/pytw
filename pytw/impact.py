import datetime
import json
import copy

import constants as Constants
import rating
import impact_status
import advisory_vuln
import cve_vuln

class Impact(object):

    """ Impact object.

    :param impact_json: Impact JSON in canonical form
    """
    def __init__(self, impact_json):
        self.__impact_json = impact_json
        self.__vuln_id = self.__impact_json[Constants.IMPACT_VULN_ID]
        self.__asset_id = self.__impact_json[Constants.IMPACT_ASSET_ID] if self.__impact_json.get(Constants.IMPACT_ASSET_ID) is not None else None
        self.__product = self.__impact_json[Constants.IMPACT_PRODUCT] if self.__impact_json.get(Constants.IMPACT_PRODUCT) is not None else None
        self.__keyword = self.__impact_json[Constants.IMPACT_KEYWORD] if self.__impact_json.get(Constants.IMPACT_KEYWORD) is not None else None
        self.__confidence = int(self.__impact_json[Constants.IMPACT_CONFIDENCE]) if self.__impact_json.get(Constants.IMPACT_CONFIDENCE) is not None else None
        self.__rating = rating.Rating(int(self.__impact_json[Constants.RATING])) if self.__impact_json.get(Constants.RATING) is not None else rating.Rating.Unknown
        self.__status = self.__get_status_enum(self.__impact_json[Constants.IMPACT_STATUS]) if self.__impact_json.get(Constants.IMPACT_STATUS) is not None else None
        self.__timestamp = datetime.datetime.strptime(self.__impact_json[Constants.IMPACT_TIMESTAMP], "%Y-%m-%d %H:%M:%S") if self.__impact_json.get(Constants.IMPACT_TIMESTAMP) is not None else None
        vuln_id = impact_json[Constants.IMPACT_VULNERABILITY][Constants.VULN_ID]
        if (vuln_id.startswith("CVE-")):
            self.__vuln = cve_vuln.CVEVuln(impact_json[Constants.IMPACT_VULNERABILITY])
        else:
            self.__vuln = advisory_vuln.AdvisoryVuln(impact_json[Constants.IMPACT_VULNERABILITY])
	

    def __get_status_enum(self, status_str):
        if (status_str == "OPEN"):
            return impact_status.Status(0)
        if (status_str == "RESOLVED"):
            return impact_status.Status(1)
        if (status_str == "IGNORED"):
            return impact_status.Status(2)
        if (status_str == "NOT_RELEVANT"):
            return impact_status.Status(3)

    def get_vuln_id(self):
        """
        :Returns a string containing the vulnerability ID
        """
        return self.__vuln_id

    def get_asset_id(self):
        """
        :Returns a string containing the asset ID
        """
        return self.__asset_id

    def get_product(self):
        """
        :Returns a string containing the product from the vulnerability
        """
        return self.__product

    def get_keyword(self):
        """
        :Returns a string containing the product from the asset
        """
        return self.__keyword

    def get_confidence(self):
        """
        :Returns the confidence for this impact
        """
        return self.__confidence

    def get_rating(self):
        """
        :Returns the rating as VulnRating enum for this impact
        """
        return self.__rating

    def get_rating_as_int(self):
        """
        :Returns the rating for this impact as an integer
        """
        return self.__rating.value

    def get_rating_as_str(self):
        """
        :Returns the rating for this impact as a string for display purposes
        """
        return self.__rating.name

    def get_status(self):
        """
        :Returns the status as a string
        """
        return self.__status

    def get_timestamp(self):
        """
        :Returns the timestamp of this impact
        """
        return self.__timestamp

    def get_vulnerability(self):
        """
        :Returns the vulnerability object associated with this impact
        """
        return self.__vuln

    def to_json(self):
        """
        :Returns JSON representation of the object
        """
        return copy.deepcopy(self.__impact_json)

    def __str__(self):
        return json.dumps(self.__impact_json)
