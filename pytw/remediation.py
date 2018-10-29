class Remediation(object):
    """ Remediation object
    Consisting of URL and Description fields
    """

    def __init__(remediation_json):
        self.__remediation_json = remediation_json
        self.__description = self.__remediations_json[VULN_REMEDIATION_DESCRIPTION]
        self.__url = self.__remediations_json[VULN_REMEDIATION_URL]

    def get_description(self):
        """
        : Returns the description for the remediation
        """
        return self.__description

    def get_url(self):
        """
        : Returns the URL for the remediation
        """
        return self.__url

def json2remediations(remediations_json):
    remediations = []
    for r in remediations_json:
        remediations.append(Remediation(r))
    return remediations


