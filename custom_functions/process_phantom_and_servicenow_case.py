def process_phantom_and_servicenow_case(container_input=None, servicenow_case=None, container_key_mapping=None, **kwargs):
    """
    Normalize case information from ServiceNow and Phantom to be in the same format
    
    Args:
        container_input: Phantom container ID (integer) or Container object (dictionary)
        servicenow_case: ServiceNow case object (dict)
        container_key_mapping: Mapping of field name between phantom and servicenow
    
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
    
    phantom.debug("process phantom and servicenow case() called")

    result = {}
    success = True
    data = {}
    error_msg = ""

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
        
        container_id = container.get("id", "")
        container_name = container.get("name", "")
        servicenow_case_id = container.get("custom_fields", {}).get("servicenow_case_id", "")
        servicenow_case_number = container.get("custom_fields", {}).get("servicenow_case_number", "")
        originate = container.get("custom_fields", {}).get("originate_from", "")
        processed_data = {}
        for i in container_key_mapping:
            phantom_key = i["phantom_key"]
            if (phantom_key == "id") or (phantom_key == "custom_fields.servicenow_case_id"):
                continue
            
            if (phantom_key.startswith("custom_fields")) and ("." in phantom_key):
                _, custom_field_name = phantom_key.split(".")
                phantom_value = container.get("custom_fields", {}).get(custom_field_name, "")
            else:
                phantom_value = container.get(phantom_key, "")

            servicenow_key = i["servicenow_key"]
            servicenow_value = servicenow_case[servicenow_key]
            
            # declare raw value to be used in status checking
            raw_servicenow_value = servicenow_value
            if i["has_mapping"] == True:
                servicenow_value = i["servicenow_value_to_phantom_value"].get(servicenow_value, "")
            
            # Convert ServiceNow group ID to group name first
            if (phantom_key == "custom_fields.assignment_group"):
                assignment_group_resp = get_assignment_group(servicenow_value.get("value", None))
                if assignment_group_resp["success"] == True:
                    servicenow_value = assignment_group_resp.get("data", {}).get("name", "")
                else:
                    raise Exception(f"Container ID: {container_id} Error while getting assignment group data (error: {assignment_group_resp['error_msg']}), skipping...")

            ###### Extra condition #####
            # Convert mapping to Phantom value depends on Business rule
            if (phantom_key == "status") and (raw_servicenow_value == "open" or raw_servicenow_value == "2"):
                if (phantom_value == "in progress") or (phantom_value == "open"):
                    servicenow_value = phantom_value

            if (phantom_key == "status") and (raw_servicenow_value == "resolved" or raw_servicenow_value == "6" or raw_servicenow_value == "closed" or raw_servicenow_value == "7"):
                if (phantom_value == "closed") or (phantom_value == "resolved"):
                    servicenow_value = phantom_value
            ###########################
            
            processed_data[phantom_key] = {"phantom": str(phantom_value), "servicenow": str(servicenow_value)}
        
        data["phantom_case_id"] = container_id
        data["phantom_case_name"] = container_name
        data["servicenow_case_id"] = servicenow_case_id
        data["servicenow_case_number"] = servicenow_case_number
        data["originate"] = originate
        data["field"] = processed_data
        data["raw_phantom"] = container
        data["raw_servicenow"] = servicenow_case

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"

    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    assert json.dumps(result)
    phantom.debug(result)
    return result

def get_assignment_group(assignment_group_id):
    import requests
    import json
    import phantom.rules as phantom

    result = {}
    success = True
    data = {}
    error_msg = ""
    phantom.debug(f"Querying for Assignment Group ID: {assignment_group_id}")
    
    try:
        servicenow_base_url = "https://krungthai.service-now.com/api/now"
        servicenow_auth = "Basic aW50ZWdyYXRpb24udXNlci5jc29jOj1WTmg6KDl7OExqajUhQmxxZnF9O2p2MyhC"
        
        if (assignment_group_id == None) or (assignment_group_id == ""):
            raise Exception(f"Invalid assignment group ID ({assignment_group_id})")        

        url = f"{servicenow_base_url}/table/sys_user_group/{assignment_group_id}"
        headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': servicenow_auth
        }

        response = requests.request("GET", url, headers=headers)
        response_json = response.json()
        response_code = response.status_code
        if response.ok:
            data = response_json.get("result", {})
        else:
            success = False
            error = response_json.get("error", {})
            message = error.get("message", "Unknown error")
            detail = error.get("detail", "Unknown detail")
            error_msg = f"HTTP Request failed with status code {response_code}. error: {error} ({detail})"
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg

    assert json.dumps(result)
    return result