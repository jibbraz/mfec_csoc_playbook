def query_servicenow(table=None, sys_id=None, **kwargs):
    """
    Args:
        table
        sys_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
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
        
        if (table == None) or (table == ""):
            raise Exception("Invalid table")
        
        if (sys_id == None) or (sys_id == ""):
            sys_id = ""

        url = f"{servicenow_base_url}/table/{table}/{sys_id}"
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
    # Return a JSON-serializable object
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result