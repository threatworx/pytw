import constants as Constants

class CVEVulnCollection(list):
    
    """ CVEVulnCollection is a collection of CVEVuln objects
    :param seq: An optional seq(list) of CVEVuln objects
    """

    def __init__(self, seq = []):
        super(CVEVulnCollection, self).__init__(seq)

    def __filterVulnsWithUpdatedField(self, updated_field):
        filtered_cve_vuln_collection = CVEVulnCollection()
        filtered_vulns = { }
        for cve in self:
            last_changed = cve.get_last_changed()
            for changed_field in last_changed:
                if(changed_field == vuln_field):
                    filtered_vulns[cve.get_id()] = cve
        return CVEVulnCollection(filtered_vulns)
                    
    def filterVulnsWithUpdatedPatches(self):
        """
        :Returns a CVEVulnCollection of filtered vulnerabilities with recently updated patches
        """
        return self.__filterVulnsWithUpdateField(Constants.VULN_PATCHES)

    def filterVulnsWithUpdatedRemediations(self):
        """
        :Returns a CVEVulnCollection of filtered vulnerabilities with recently updated remediations
        """
        return self.__filterVulnsWithUpdateField(Constants.VULN_REMEDIATIONS)

    def filterVulnsWithUpdatedExploits(self):
        """
        :Returns a CVEVulnCollection of filtered vulnerabilities with recently updated exploits
        """
        return self.__filterVulnsWithUpdateField(Constants.VULN_EXPLOITS)

