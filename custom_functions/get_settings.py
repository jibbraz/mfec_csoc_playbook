def get_settings(**kwargs):
    """
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
        ok, message, settings_list = phantom.get_list(list_name="servicenow_playbook_settings")
        if ok == False:
            raise Exception(f"Error occured while getting a value from the custom list: settings. {message}")
        settings = {}
    
        row_setting = 1
        for row in settings_list:
            key = row[0]
            value = row[1]
            if key == None:
                phantom.debug(f"Settings Key missing at row {row_setting}")
                row_setting += 1
                continue
            if value == None:
                phantom.debug(f"Settings Value missing at row {row_setting}")
                row_setting += 1
                continue
            settings[key] = value
            row_setting += 1
        data = settings

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    # settings dict example
    # {
    #     "maximum_artifact": "10"
    # }
    
    # Return a JSON-serializable object
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result
