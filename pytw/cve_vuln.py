import core_vuln
import advisory_vuln
import constants as Constants

class CVEVuln(core_vuln.CoreVuln):
    """ CVE vulnerability object
    """
    def __init__(self, vuln_json):
        super(CVEVuln, self).__init__(vuln_json)
        self.__advisories = []
        for advisory in vuln_json[Constants.VULN_ADVISORIES]:
            self.__advisories.append(advisory_vuln.AdvisoryVuln(advisory))

    def get_advisories(self):
        """
        : Returns an array of AdvisoryVulns which are referring to this CVE
        """
        return self.__advisories

