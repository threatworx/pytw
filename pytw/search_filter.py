import constants as Constants
import exceptions

class SearchFilter(object):
    """ SearchFilter obobjectject 
    Allows one to specify multiple search filters for the search operation
    """
    
    def __init__(self, window_start=None, window_end=None, offset=None, limit=None):
        self.__search_dict = {}

    def add_filter(self, search_filter, filter_params=None):
        """ Add specified search_filter along with filter_params to SearchFilter object
        """
        if search_filter in Constants.SUPPORTED_SEARCH_FILTERS:
            self.__search_dict[search_filter] = filter_params if filter_params != None else ""
        else:
            raise exceptions.PyTWError("Unsupported filter: " + search_filter)

    def to_dict(self):
        """ Get the search filter dict object from SearchFilter
        """
        return self.__search_dict

    def __str__(self):
        return str(self.__search_dict)

