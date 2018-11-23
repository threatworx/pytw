import constants as Constants

class SearchParams(object):
    """ SearchParams object 
    Consisting of multiple parameters related to search operation
    """
    
    def __init__(self, window_start=None, window_end=None, offset=None, limit=None):
        self.window_start = window_start if window_start is not None else 1
        self.window_end = window_end if window_end is not None else 0
        self.offset = offset if offset is not None else 0
        self.limit = limit if limit is not None else -1

    def to_dict(self):
        """ Add search parameters to input dict object
        """
        dict_obj = {}
        dict_obj[Constants.SEARCH_PARAM_WINDOW_START] = self.window_start
        dict_obj[Constants.SEARCH_PARAM_WINDOW_END] = self.window_end
        dict_obj[Constants.SEARCH_PARAM_OFFSET] = self.offset
        dict_obj[Constants.SEARCH_PARAM_LIMIT] = self.limit
        return dict_obj

    def __str__(self):
        s = "[" + Constants.SEARCH_PARAM_WINDOW_START + "=" + str(self.window_start) + "]"
        s = s + "[" + Constants.SEARCH_PARAM_WINDOW_END + "=" + str(self.window_end) + "]"
        s = s + "[" + Constants.SEARCH_PARAM_OFFSET + "=" + str(self.offset) + "]"
        s = s + "[" + Constants.SEARCH_PARAM_LIMIT + "=" + str(self.limit) + "]"
        return s

