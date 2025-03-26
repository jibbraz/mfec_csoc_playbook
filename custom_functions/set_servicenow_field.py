def set_servicenow_field(servicenow_case_id=None, field_name=None, value=None, **kwargs):
    """
    Generate HTTP Request and send for ServiceNow case Patching
    
    Args:
        servicenow_case_id: Container ID to run this function
        field_name
        value
    
    Returns a JSON-serializable object that implements the configured data paths:
        success: List of incident worknotes from ServiceNow (Dates arranged in ascending order)
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import requests
    
    result = {}
    
    success = True
    data = {}
    error_msg = ""
    
    try:
        servicenow_base_url = "https://krungthai.service-now.com/api/now"
        servicenow_auth = "Basic aW50ZWdyYXRpb24udXNlci5jc29jOj1WTmg6KDl7OExqajUhQmxxZnF9O2p2MyhC"
        
        if (servicenow_case_id == None) or (servicenow_case_id == ""):
            raise Exception(f"Invalid ServiceNow Incident ID ({servicenow_case_id})")        

        url = f"{servicenow_base_url}/table/incident/{servicenow_case_id}"
        headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': servicenow_auth
        }

        payload = json.dumps({
                  str(field_name): value
                })

        response = requests.request("PATCH", url, headers=headers, data=payload)
        response_json = response.json()
        response_code = response.status_code
        if response.ok:
            data = response_json
        else:
            success = False
            error = response_json.get("error", {})
            message = error.get("message", "Unknown error")
            detail = error.get("detail", "Unknown detail")
            error_msg = f"ServiceNow case ID: {servicenow_case_id} HTTP Request failed with status code {response_code}. error: {error} ({detail})"
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

