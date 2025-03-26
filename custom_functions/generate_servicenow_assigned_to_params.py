def generate_servicenow_assigned_to_params(servicenow_case_info=None, servicenow_settings=None, servicenow_case_id=None, servicenow_case_table=None, **kwargs):
    """
    Args:
        servicenow_case_info: ServiceNow case info (field) from generate_serviecnow_case_info function
        servicenow_settings
        servicenow_case_id
        servicenow_case_table
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    phantom.debug("generate_servicenow_assigned_to_params() called")
    
    result = {}
    success = True
    data = {}
    error_msg = ""
    
    
    try:
        if isinstance(servicenow_case_info, str):
            case_info = json.loads(servicenow_case_info)
        elif isinstance(servicenow_case_info, dict):
            case_info = servicenow_case_info
        else:
            raise Exception(f"servicenow_case_info {servicenow_case_info} is neither a string or dictionary")
            
        if "assignment_group" in case_info:
            # Get sasigned_to value
            phantom_assignment_group = case_info.get("assignment_group", "").lower()
            default_value_key = f"{phantom_assignment_group}_assigned_to"
            assigned_to = servicenow_settings.get(default_value_key, "")
            
            field = case_info.copy()
            
            # To update assignde_to field, it requires to delete assignment_group field first
            del field["assignment_group"]
            field["assigned_to"] = assigned_to
            
        else:
            field = case_info
            
        data["servicenow_case_id"] = servicenow_case_id
        data["servicenow_case_table"] = servicenow_case_table
        data["field"] = field
        
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    assert json.dumps(result)
    phantom.debug(result)
    return result