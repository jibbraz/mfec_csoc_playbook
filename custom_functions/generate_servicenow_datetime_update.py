def generate_servicenow_datetime_update(servicenow_case_id=None, datetime_str=None, **kwargs):
    """
    Create update statement for ServiceNow API to update time in front-end datetime format
    
    Args:
        servicenow_case_id
        datetime_str: datetime string in correct format
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime
    
    result = {}
    success = True
    data = {}
    error_msg = ""
    
    try:
        path = f"{servicenow_case_id}?sysparm_input_display_value=true"
        formatted_datetime = datetime.strptime(datetime_str, "%d/%m/%Y %H:%M:%S")
        formatted_datetime_str = formatted_datetime.strftime("%Y-%m-%d %H:%M:%S")
        data["servicenow_case_id"] = path
        data["unformatted_datetime_str"] = datetime_str
        data["formatted_datetime_str"] = formatted_datetime_str
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