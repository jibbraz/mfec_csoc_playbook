def generate_servicenow_case_info(container_input=None, container_key_mapping=None, is_new_case=None, phantom_based_field=None, origin_based_field=None, assignment_group_update=None, cancel_case=None, servicenow_settings=None, incident_type_update=None, new_case_assignment_group_allowed_list=None, **kwargs):
    """
    Generate Parameters for ServiceNow case creation/updating
    
    Args:
        container_input: Phantom container ID (integer) or Container object (dictionary)
        container_key_mapping: Mapping of field name between phantom and servicenow
        is_new_case: Is generating case information a new case? Default is yes
        phantom_based_field: List of Phantom-based field
        origin_based_field: List of Origin-based field
        assignment_group_update
        cancel_case
        servicenow_settings
        incident_type_update
        new_case_assignment_group_allowed_list
    
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
    
    phantom.debug("generate servicenow case info() called")

    result = {}
    success = True
    data = {}
    error_msg = ""
    
    if str(is_new_case).upper() == "NO":
        is_new_case = False
    else:
        is_new_case = True
    
    # Preparing default parameter value
    if assignment_group_update == None:
        assignment_group_update = True
        
    if cancel_case == None:
        cancel_case = False
    
    if incident_type_update == None:
        incident_type_update = True
    
    if new_case_assignment_group_allowed_list == None:
        new_case_assignment_group_allowed_list = []
        
    check_default_assignment_group = True

    ###################################
    
    if not phantom_based_field:
        phantom_based_field = []
    if not origin_based_field:
        origin_based_field = []
    try:
        if str(container_input).isdigit():
            container_input = int(container_input)
    
        if isinstance(container_input, int):
            container = phantom.get_container(container_input)
            if container == None:
                raise Exception(f"Container ID {container_input} not found")
        elif isinstance(container_input, dict):
            container = container_input
        else:
            raise Exception(f"container_input {container_input} is neither a int or a dictionary")
        
        container_id = container.get("id")
        origin = container.get("custom_fields", {}).get("originate_from", "")
        servicenow_case_table = servicenow_settings.get("servicenow_case_table", "")
        servicenow_case_category = servicenow_settings.get("servicenow_case_category", "")

        field = {"category": servicenow_case_category}
        
        for i in container_key_mapping:
            phantom_key = i["phantom_key"]
            
            # In a new case, Phantom case doesn't have ServiceNow case ID
            if (is_new_case == True) and (phantom_key == "custom_fields.servicenow_case_id"):
                continue
            
            # For new case. if assignment_group is not in allowed list, set to blank and skip checking for default assignment group
            if (is_new_case == True) and (phantom_key == "custom_fields.assignment_group"):
                phantom_assignment_group = str(container.get("custom_fields", {}).get("assignment_group", ""))
                if (phantom_assignment_group not in new_case_assignment_group_allowed_list) and (phantom_assignment_group != ""):
                    check_default_assignment_group = False
                    field["assignment_group"] = ""
                    continue
            
            # if assignment_group is not updated, assign the default people. else, delete the assigned people
            if (assignment_group_update == False) and (phantom_key == "custom_fields.assignment_group"):
                phantom_assignment_group = str(container.get("custom_fields", {}).get("assignment_group", "")).lower()
                default_assign_to_key = f"{phantom_assignment_group}_assigned_to"
                default_assigned_to = servicenow_settings.get(default_assign_to_key, "")
                # No default value -> skip assignment section
                if default_assigned_to == "":
                    continue
                else:
                    field["assigned_to"] = default_assigned_to
                    continue
            elif (assignment_group_update == True) and (phantom_key == "custom_fields.assignment_group"):
                field["assigned_to"] = ""
            
            # For updating case, use only Phantom-based and Origin-based fields to update
            if (is_new_case == False) and (phantom_key not in phantom_based_field) and (phantom_key not in origin_based_field):
                continue
            if (is_new_case == False) and (phantom_key in origin_based_field) and (origin != "Phantom"):
                continue
            
            # Normal action
            if (phantom_key.startswith("custom_fields")) and ("." in phantom_key):
                _, phantom_key = phantom_key.split(".")
                phantom_value = container.get("custom_fields", {}).get(phantom_key, "")
            else:
                phantom_value = container.get(phantom_key, "")

            servicenow_key = i["servicenow_key"]
            if i["has_mapping"] == True:
                servicenow_value = i["phantom_value_to_servicenow_value"].get(phantom_value, "")
            else:
                servicenow_value = phantom_value
            field[servicenow_key] = servicenow_value

            
        case_status = container.get("status")
        
        # Send default close code and close note if phantom resolved case without them
        if (case_status == "resolved") or (case_status == "closed"):
            close_code = field.get("close_code", "")
            close_notes = field.get("close_notes", "")
            if close_code == "":
                close_code = servicenow_settings.get("default_servicenow_close_code", "")
                field["close_code"] = close_code
                close_code_phantom = {"custom_fields": {"close_code": close_code}}
                ok, message = phantom.update(container, close_code_phantom)
                if not ok:
                    phantom.debug(f"ERROR: Cannot update default close_code to container {container_id}: {message}")
            if close_notes == "":
                close_notes = servicenow_settings.get("default_servicenow_close_note", "")
                field["close_notes"] = close_notes
                close_note_phantom = {"custom_fields": {"close_notes": close_notes}}
                ok, message = phantom.update(container, close_note_phantom)
                if not ok:
                    phantom.debug(f"ERROR: Cannot update default close_notes to container {container_id}: {message}")
            field["u_cause_notes"] = close_notes
            
        # Send hold reason if update ServiceNow status to "On hold"
        if (case_status == "pending"):
            field["hold_reason"] = servicenow_settings.get("default_servicenow_hold_reason", "")
        
        # Change to cancel if cancel case is required
        if cancel_case:
            field["state"] = "8"
        
        if incident_type_update:
            field["u_subcategory2"] = servicenow_settings.get("default_servicenow_subcat2", "")
        
        # Initialize new case and assign default values
        if is_new_case == True:
            field["caller_id"] = servicenow_settings.get("default_servicenow_caller", "")
            field["u_affected_id"] = servicenow_settings.get("default_servicenow_affected_person", "")
            field["business_service"] = servicenow_settings.get("default_servicenow_business_service", "")
            field["contact_type"] = servicenow_settings.get("default_servicenow_channel", "")
            if field["description"] == "":
                description = servicenow_settings.get("default_servicenow_description", "")
                field["description"] = description
                description_phantom = {"description": description}
                ok, message = phantom.update(container, description_phantom)
                if not ok:
                    phantom.debug(f"ERROR: Cannot update default description to container {container_id}: {message}")
            if field["assignment_group"] == "" and check_default_assignment_group:
                assignment_group = servicenow_settings.get("default_servicenow_assignment_group", "")
                field["assignment_group"] = assignment_group
                assignment_group_phantom = {"custom_fields": {"assignment_group": assignment_group}}
                ok, message = phantom.update(container, assignment_group_phantom)
                if not ok:
                    phantom.debug(f"ERROR: Cannot update default assignment_group to container {container_id}: {message}")
        
        # build parameters list for 'create_ticket' call
        parameters = {
            "servicenow_case_id": "",
            "table": servicenow_case_table,
            "field": json.dumps(field),
            "raw": container
        }
        if is_new_case == False:
            parameters["servicenow_case_id"] = container.get("custom_fields", {}).get("servicenow_case_id", "")
        data = parameters
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"

    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    assert json.dumps(result)
    phantom.debug(result)
    return result