def compare_assignment_group_and_status(servicenow_case_obj=None, **kwargs):
    """
    Args:
        servicenow_case_obj
    
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
    data = {}
    error_msg = ""

    try:
        if not isinstance(servicenow_case_obj, dict):
            raise Exception("Invalid servicenow_case_obj, servicenow_case_obj should be dictionary")

        phantom_case_id = servicenow_case_obj.get("u_phantom_case_id")
        if not str(phantom_case_id).isdigit():
            raise Exception(f"Invalid phantom_case_id '{phantom_case_id}', phantom_case_id is not a number")
        
        container = phantom.get_container(phantom_case_id)
        if container == None:
            raise Exception(f"Container ID {phantom_case_id} not found")
        
        skip = False
        assignment_group_update = False
        cancel_case = False
        incident_type_update = False
        
        # Check if servicenow assingment group API sends the default value
        servicenow_assignment_group_obj = servicenow_case_obj.get("assignment_group", {})
        if isinstance(servicenow_assignment_group_obj, str):
            servicenow_assignment_group = servicenow_assignment_group_obj
        else:
            servicenow_assignment_group = servicenow_case_obj.get("assignment_group", {}).get("display_value", "")
        phantom_assignment_group = container.get("custom_fields", {}).get("assignment_group", "")
        
        phantom.debug(f"Phantom assignment group is {phantom_assignment_group}, ServiceNow is {servicenow_assignment_group}")
        if phantom_assignment_group != servicenow_assignment_group:
            assignment_group_update = True
            
        servicenow_case_status = str(servicenow_case_obj.get("state", ""))
        phantom_case_status = str(container.get("status", ""))
        
        phantom.debug(f"Phantom case status is {phantom_case_status}, ServiceNow is {servicenow_case_status}")
        
        # If both cases have the same status for cancel or resolved, skip them to not sync anymore
        if (phantom_case_status == "cancelled") and (servicenow_case_status == "Canceled" or servicenow_case_status == "8"):
            skip = True
        elif (phantom_case_status == "resolved" or phantom_case_status == "closed") and (servicenow_case_status == "Resolved" or servicenow_case_status == "6" or servicenow_case_status == "Closed" or servicenow_case_status == "7"):
            skip = True
        
        # If some of them has cancel status, cancel in the other side too
        if (phantom_case_status == "cancelled") or (servicenow_case_status == "Canceled" or servicenow_case_status == "8"):
            cancel_case = True
        
        phantom_subcat = container.get("custom_fields", {}).get("Incident Type", "")
        servicenow_subcat = servicenow_case_obj.get("subcategory", "")
        
        phantom.debug(f"Phantom Incident Type is {phantom_subcat}, ServiceNow is {servicenow_subcat}")
        
        # Compare Incident type vs Category
        if phantom_subcat.strip() not in servicenow_subcat:
            incident_type_update = True
        
        data["skip"] = skip
        data["cancel_case"] = cancel_case
        data["assignment_group_update"] = assignment_group_update
        data["incident_type_update"] = incident_type_update
        data["raw_phantom"] = container
        data["raw_servicenow"] = servicenow_case_obj
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
