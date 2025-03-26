def generate_servicenow_frontend_query(servicenow_case_id=None, **kwargs):
    """
    Add query statement for ServiceNow API to get information in front-end format
    
    Args:
        servicenow_case_id
    
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
    data = ""
    error_msg = ""
    
    try:
        data = f"{servicenow_case_id}?sysparm_display_value=true"
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