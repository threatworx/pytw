import constants as Constants

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
        self.__url = self.__patch_json[Constants.VULN_PATCH_URL]

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

def json2patches(patches_json):
    patches = []
    for p in patches_json:
        patches.append(Patch(p))
    return patches
