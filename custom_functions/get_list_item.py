def get_list_item(custom_list_name=None, **kwargs):
    """
    Return list of item in specified custom list
    
    Args:
        custom_list_name
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    result = {}
    success = True
    data = []
    error_msg = ""
    
    try:
        ok, message, item = phantom.get_list(list_name=custom_list_name)
        if ok == False:
            raise Exception(f"Error occured while getting value from the custom list: {custom_list_name}. {message}")
    
        for row in item:
            field = [col for col in row if (col != "") and (col != None)]
            data += field
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg

    # Return a JSON-serializable object
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result
