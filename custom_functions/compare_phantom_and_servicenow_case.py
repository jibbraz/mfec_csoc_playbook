def compare_phantom_and_servicenow_case(processed_case=None, phantom_based_field=None, servicenow_based_field=None, origin_based_field=None, **kwargs):
    """
    compare processed case between Phantom and ServiceNow and send out the diff information
    
    Args:
        processed_case
        phantom_based_field
        servicenow_based_field
        origin_based_field
    
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
    

    ph_diff = False
    sn_diff = False
    ph_override = []
    sn_override = []
    assignment_group_update = False
    cancel_case = False
    skip = False
    incident_type_update = False
    
    try:
        originate = processed_case["originate"]
        container_id = processed_case["phantom_case_id"]
        servicenow_case_id = processed_case["servicenow_case_id"]
        raw_phantom = processed_case["raw_phantom"]
        raw_servicenow = processed_case["raw_servicenow"]
        if (originate == None) or (originate == ""):
            raise Exception(f"failed to get originate_from value from container ID: {container_id}. skipping...")
        for field_name, value in processed_case["field"].items():
            ph_val = value["phantom"]
            sn_val = value["servicenow"]

            # IF CASE CANCELLED, CANCEL IN THE OTHER SIDE TOO
            if field_name == "status":
                if (ph_val == sn_val == "cancelled") or (ph_val == sn_val == "resolved") or (ph_val == sn_val == "closed"):
                    skip = True
                    continue
                if (ph_val == "cancelled") and (sn_val != "cancelled"):
                    ph_override.append(field_name)
                    ph_diff = True
                    cancel_case = True
                    continue
                elif (sn_val == "cancelled") and (ph_val != "cancelled"):
                    sn_override.append(field_name)
                    sn_diff = True
                    cancel_case = True
                    continue
                
            if ph_val != sn_val:
                if (field_name in phantom_based_field) or (field_name in origin_based_field and originate == "Phantom"):
                    ph_override.append(field_name)
                    ph_diff = True
                elif (field_name in servicenow_based_field) or (field_name in origin_based_field and originate == "ServiceNow"):
                    sn_override.append(field_name)
                    sn_diff = True
                else:
                    phantom.debug(f"Container ID: {container_id}. Field name {field_name} is not a Phantom-based, ServiceNow-based, or Origin-based. skipping...")
                
                if field_name == "custom_fields.assignment_group":
                    assignment_group_update = True
                if field_name == "custom_fields.Incident Type":
                    incident_type_update = True
        
        data = processed_case.copy()
        data["phantom_based_diff"] = ph_diff
        data["phantom_override_field"] = ph_override
        data["servicenow_based_diff"] = sn_diff
        data["servicenow_override_field"] = sn_override
        data["assignment_group_update"] = assignment_group_update
        data["cancel_case"] = cancel_case
        data["skip"] = skip
        data["incident_type_update"] = incident_type_update
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    
    # Return a JSON-serializable object
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result