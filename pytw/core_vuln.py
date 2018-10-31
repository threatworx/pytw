import datetime
import json
import copy

import constants as Constants
import product
import remediation
import patch
import exploit

class CoreVuln(object):

    """ Cure Vulnerability object.

    :param vuln_json: Vulnerability JSON in canonical form
    """
    def __init__(self, vuln_json):
        self.__vuln_json = vuln_json
        self.__id = self.__vuln_json[Constants.VULN_ID]
        self.__title = self.__vuln_json[Constants.VULN_TITLE] if self.__vuln_json.get(Constants.VULN_TITLE)!=None else None
        self.__summary = self.__vuln_json[Constants.VULN_SUMMARY] if self.__vuln_json.get(Constants.VULN_SUMMARY)!=None else None
        self.__vuln_types = self.__vuln_json[Constants.VULN_VULNERABILITY_TYPES] if self.__vuln_json.get(Constants.VULN_VULNERABILITY_TYPES)!=None else None
        self.__cvss_score = self.__vuln_json[Constants.VULN_CVSS_SCORE] if self.__vuln_json.get(Constants.VULN_CVSS_SCORE)!=None else None
        self.__cvss_vector = self.__vuln_json[Constants.VULN_CVSS_VECTOR] if self.__vuln_json.get(Constants.VULN_CVSS_VECTOR)!=None else None
        self.__rating = self.__vuln_json[Constants.VULN_RATING] if self.__vuln_json.get(Constants.VULN_RATING)!=None else None
        self.__published_datetime = datetime.datetime.strptime(self.__vuln_json[Constants.VULN_PUBLISHED_DATETIME], "%Y-%m-%d %H:%M:%S") if self.__vuln_json.get(Constants.VULN_PUBLISHED_DATETIME)!=None else None
        self.__last_modified_datetime = datetime.datetime.strptime(self.__vuln_json[Constants.VULN_LAST_MODIFIED_DATETIME], "%Y-%m-%d %H:%M:%S") if self.__vuln_json.get(Constants.VULN_LAST_MODIFIED_DATETIME)!=None else None
        self.__last_change = self.__vuln_json[Constants.VULN_LAST_CHANGE] if self.__vuln_json.get(Constants.VULN_LAST_CHANGE)!=None else None
        self.__references = self.__vuln_json[Constants.VULN_REFERENCES] if self.__vuln_json.get(Constants.VULN_REFERENCES)!=None else None
        self.__products = product.json2products(self.__vuln_json[Constants.VULN_PRODUCTS]) if self.__vuln_json.get(Constants.VULN_PRODUCTS)!=None else None
        self.__exploits = exploit.json2exploits(self.__vuln_json[Constants.VULN_EXPLOITS]) if self.__vuln_json.get(Constants.VULN_EXPLOITS)!=None else None
        self.__remediations = remediation.json2remediations(self.__vuln_json[Constants.VULN_REMEDIATIONS]) if self.__vuln_json.get(Constants.VULN_REMEDIATIONS)!=None else None
        self.__patches = patch.json2patches(self.__vuln_json[Constants.VULN_PATCHES]) if self.__vuln_json.get(Constants.VULN_PATCHES)!=None else None

    def get_id(self):
        """
        :Returns a string containing the vulnerability ID
        """
        return self.__id

    def get_title(self):
        """
        :Returns a string containing the vulnerability title
        """
        return self.__title

    def get_summary(self):
        """
        :Returns a string containing the vulnerability summary
        """
        return self.__summary

    def get_vuln_types(self):
        """
        :Returns an array containing strings of vulnerability types
        """
        return self.__vuln_types

    def get_cvss_score(self):
        """
        :Returns the CVSS score
        """
        return self.__cvss_score

    def get_cvss_vector(self):
        """
        :Returns the CVSS vector
        """
        return self.__cvss_vector

    def get_rating(self):
        """
        :Returns the rating as a string
        """
        return self.__rating

    def get_published_datetime(self):
        """
        :Returns the published date as datetime
        """
        return self.__published_datetime

    def get_last_modified_datetime(self):
        """
        :Returns the last modified date as datetime
        """
        return self.__last_modified_datetime

    def get_last_change(self):
        """
        :Returns the list of last changed fields
        """
        return self.__last_change

    def get_references(self):
        """
        :Returns references as an array of URL strings
        """
        return self.__references

    def get_products(self):
        """
        :Returns the list of products
        """
        return self.__products

    def get_exploits(self):
        """
        :Returns the list of exploits
        """
        return self.__exploits

    def get_remediations(self):
        """
        :Returns the list of remediations
        """
        return self.__remediations

    def get_patches(self):
        """
        :Returns the list of patches
        """
        return self.__patches

    def toJson(self):
        """
        :Returns JSON representation of the object
        """
        return copy.deepcopy(self.__vuln_json)

    def __str__(self):
        return json.dumps(self.__vuln_json)
