import core_vuln
import advisory_vuln
import constants as Constants

class CVEVuln(core_vuln.CoreVuln):
    """ CVE vulnerability object
    """
    def __init__(self, vuln_json):
        super(CVEVuln, self).__init__(vuln_json)
        self.__external_references = []
        for ext_ref in vuln_json[Constants.VULN_EXTERNAL_REFERENCES]:
            self.__external_references.append(advisory_vuln.AdvisoryVuln(ext_ref))

    def get_external_references(self):
        """
        : Returns an array of AdvisoryVulns which are referring to this CVE
        """
        return self.__external_references

