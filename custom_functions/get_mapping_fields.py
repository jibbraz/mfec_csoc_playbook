def get_mapping_fields(key_mapping_list_name=None, **kwargs):
    """
    Return a list of mapping between Phantom key name to ServiceNow key name with its value.
    
    Args:
        key_mapping_list_name
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from collections import defaultdict
    
    result = {}
    success = True
    data = []
    error_msg = ""
    
    try:
        ok, message, container_key_mapping_list = phantom.get_list(list_name=key_mapping_list_name)
        if ok == False:
            raise Exception(f"Error occured while getting value from the custom list: phantom_keyname_to_servicenow_keyname_mapping. {message}")
        container_key_mapping = []
        
        row_mapping = 1
        for row in container_key_mapping_list:
            data = {}
            has_mapping = True
            
            phantom_key = row[0]
            servicenow_key = row[1]
            
            if phantom_key == None:
                phantom.debug(f"Phantom Key missing at custom list {key_mapping_list_name} row {row_mapping}")
                row_mapping += 1
                continue
            if servicenow_key == None:
                phantom.debug(f"ServiceNow Key missing at custom list {key_mapping_list_name} row {row_mapping}")
                row_mapping += 1
                continue

            customlist_name = f"{phantom_key}_mapping"

            ok, message, variable_mapping_list = phantom.get_list(list_name=customlist_name)
            if ok == False:
                phantom.debug(f"Error occured while getting value from the custom list: {customlist_name} ({message}). system will assign empty mapping value to {phantom_key} field.")
                variable_mapping_list = []
                has_mapping = False

            sn_value_mapping = {}
            pht_value_mapping = {}
            row_value = 1
            for value in variable_mapping_list:
                phantom_value = value[0]
                servicenow_value = value[1]

                if phantom_value == None:
                    phantom.debug(f"Phantom value missing at custom list {customlist_name} row {row_value}")
                    row_value += 1
                    continue
                if servicenow_value == None:
                    phantom.debug(f"ServiceNow value missing at custom list {customlist_name} row {row_value}")
                    row_value += 1
                    continue

                sn_value_mapping[servicenow_value] = phantom_value
                pht_value_mapping[phantom_value] = servicenow_value
                
                ###### Extra condition #####
                if (phantom_key == "status") and (servicenow_value == "2"):
                    sn_value_mapping[servicenow_value] = "open"
                if (phantom_key == "status") and (servicenow_value == "6"):
                    sn_value_mapping[servicenow_value] = "resolved"
                if (phantom_key == "severity") and (servicenow_value == "0"):
                    sn_value_mapping[servicenow_value] = "critical"
                ###########################
                
                row_value += 1
            
            data["phantom_key"] = phantom_key
            data["servicenow_key"] = servicenow_key
            data["has_mapping"] = has_mapping
            data["servicenow_value_to_phantom_value"] = sn_value_mapping
            data["phantom_value_to_servicenow_value"] = pht_value_mapping
            
            container_key_mapping.append(data)
            row_mapping += 1

        data = container_key_mapping

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
        
    # [
    #     {
    #         "has_mapping": true,
    #         "phantom_key": "severity",
    #         "phantom_value_to_servicenow_value": {
    #             "critical": "1",
    #             "high": "2",
    #             "informational": "5",
    #             "low": "4",
    #             "medium": "3"
    #         },
    #         "servicenow_key": "u_security_severity",
    #         "servicenow_value_to_phantom_value": {
    #             "1": "critical",
    #             "2": "high",
    #             "3": "medium",
    #             "4": "low",
    #             "5": "informational"
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
    
    # Return a JSON-serializable object
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result