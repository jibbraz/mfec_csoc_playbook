def filter_phantom_allowed_case(container_list=None, allow_list=None, **kwargs):
    """
    Filters and returns a list of container that belong to allowed list of incident type
    
    Args:
        container_list
        allow_list
    
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
        if not isinstance(container_list, list):
            raise Exception(f"container_list is not a list")
        for c in container_list:
            container_id = c.get("id")
            inc_type = c.get("custom_fields", {}).get("Incident Type", "")
            if inc_type in allow_list:
                data.append(c)
            else:
                phantom.debug(f"Container ID: {container_id} with Incident Type {inc_type} is not allowed.")
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
