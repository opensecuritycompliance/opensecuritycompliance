def is_valid_key(element, key, array_check:bool=False):
    if not element or not key or key not in element:
        return False
    value = element[key]
    if ((isinstance(value, int) and value >= 0) or value):
        if array_check:
            if (isinstance(value,list) or isinstance(value,set) or isinstance(value,tuple) and len(value)>0):
                return True
            else:
                return False
        return True
    
    return False


def is_valid_array(ele, key):
    return is_valid_key(ele, key, array_check=True)
    