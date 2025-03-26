def generate_phantom_case_info(servicenow_case=None, container_key_mapping=None, is_new_case=None, servicenow_based_field=None, origin_based_field=None, assignment_group=None, cancel_case=None, **kwargs):
    """
    Generate Parameters from artifact or REST API response for Phantom case updating
    
    Args:
        servicenow_case: ServiceNow case object (dict) to generate Phantom information
        container_key_mapping: Mapping of field name between phantom and servicenow
        is_new_case: Is generating case information a new case? Default is yes
        servicenow_based_field: List of ServiceNow-based field
        origin_based_field: List of Origin-based field
        assignment_group
        cancel_case
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    # container_key_mapping Example:
    # [
    #     {
    #         "has_mapping": true,
    #         "phantom_key": "sensitivity",
    #         "phantom_value_to_servicenow_value": {
    #             "amber": "2",
    #             "green": "3",
    #             "red": "1",
    #             "white": "4"
    #         },
    #         "servicenow_key": "impact",
    #         "servicenow_value_to_phantom_value": {
    #             "1": "red",
    #             "2": "amber",
    #             "3": "green",
    #             "4": "white"
    #         }
    #     },
    #     {
    #         "has_mapping": false,
    #         "phantom_key": "name",
    #         "phantom_value_to_servicenow_value": {},
    #         "servicenow_key": "short_description",
    #         "servicenow_value_to_phantom_value": {}
    #     }
    # ]
    
    phantom.debug("generate phantom case info() called")

    result = {}
    success = True
    data = {}
    error_msg = ""
    origin = ""

    is_new_case = str(is_new_case)
    if (is_new_case.upper() == "NO"):
        is_new_case = False
    else:
        is_new_case = True
        
    if cancel_case == None:
        cancel_case = False
        
    if not servicenow_based_field:
        servicenow_based_field = []
    if not origin_based_field:
        origin_based_field = []
    try:
        if is_new_case == False:
            servicenow_case_id = servicenow_case.get("sys_id")
            phantom_case_id = servicenow_case.get("u_phantom_case_id")
            container = phantom.get_container(phantom_case_id)
            if container == None:
                raise Exception(f"Linked Phantom case ID {phantom_case_id} of ServiceNow case ID {servicenow_case_id} is not found. skipping...")
            origin = container.get("custom_fields", {}).get("originate_from", "")

        parameters = {}
        custom_fields = {}
        
        # If Case Cancelled on Servicenow, Cancel on Phantom too
        servicenow_state = servicenow_case.get("state")
        if servicenow_state == "Canceled":
            parameters["status"] = "cancelled"

        for i in container_key_mapping:
            is_custom = False
            phantom_key = i["phantom_key"]
            
            # For new case, ServiceNow case doesn't have Phantom case ID. skip it
            if (is_new_case == True) and (phantom_key == "id"):
                continue
            
            # For new case, Assign the assignment group as per input
            if (is_new_case == True) and (phantom_key == "custom_fields.assignment_group") and (assignment_group):
                custom_fields["assignment_group"] = assignment_group
                continue
            
            # For updating case, use only ServiceNow-based and Origin-based fields to update
            if (is_new_case == False) and (phantom_key not in servicenow_based_field) and (phantom_key not in origin_based_field):
                continue
            if (is_new_case == False) and (phantom_key in origin_based_field) and (origin != "ServiceNow"):
                continue
            
            # Normal situation
            if (phantom_key.startswith("custom_fields")) and ("." in phantom_key):
                is_custom = True
                _, phantom_key = phantom_key.split(".")
            
            servicenow_key = i["servicenow_key"]
            servicenow_value = servicenow_case.get(servicenow_key, "")

            if i["has_mapping"] == True:
                phantom_updated_value = i["servicenow_value_to_phantom_value"].get(servicenow_value, "")
            else:
                phantom_updated_value = servicenow_value
            
            if is_custom:
                custom_fields[phantom_key] = phantom_updated_value
            else:
                parameters[phantom_key] = phantom_updated_value

        parameters["custom_fields"] = custom_fields
        if is_new_case == False:
            parameters["id"] = servicenow_case.get("u_phantom_case_id", "")

        # Change to cancel if cancel case is required
        if cancel_case:
            parameters["status"] = "cancelled"
        
        data["formatted"] = parameters
        data["raw"] = servicenow_case

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"

    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    assert json.dumps(result)
    phantom.debug(result)
    return result