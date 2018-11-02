import constants as Constants
import json

class Patch(object):
    """ Patch object 
    Consisting of Product and URL
    """
    
    def __init__(self, patch_json):
        self.__patch_json = patch_json
        self.__id = self.__patch_json[Constants.VULN_PATCH_ID]
        if (self.__patch_json.get(Constants.VULN_PATCH_PRODUCT) != None):
            self.__product = self.__patch_json[Constants.VULN_PATCH_PRODUCT]
        else:
            # TODO - remove this
            self.__product = self.__patch_json["description"]
        if Constants.VULN_PATCH_URL in self.__patch_json:
            self.__url = self.__patch_json[Constants.VULN_PATCH_URL]
        else:
            self.__url = ""

    def get_product(self):
        """
        :Returns the patch product
        """
        return self.__product

    def get_url(self):
        """
        :Returns the URL of patch
        """
        return self.__url

    def toJson(self):
        """
        :Returns JSON representation of the object
        """
        return self.__patch_json

    def __str__(self):
        return json.dumps(self.__patch_json)

def json2patches(patches_json):
    patches = []
    for p in patches_json:
        patches.append(Patch(p))
    return patches
