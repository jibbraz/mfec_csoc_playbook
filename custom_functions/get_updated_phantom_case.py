def get_updated_phantom_case(minute_ago=None, **kwargs):
    """
    Return list of updated phantom cases.
    
    minute_ago = amount of minutes ago to determine whether the case is updated. Check with container_update_time
    
    Args:
        minute_ago: amount of minutes ago to determine whether the case is updated. Check with container_updated_time
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime, timedelta
    import urllib.parse
    
    result = {}
    success = True
    data = []
    error_msg = ""
    
    try:
        if not (str(minute_ago).isdigit()):
            raise Exception("minute_ago is not a number")
            
        minute_ago = int(minute_ago)
        datetime_now = datetime.now().replace(microsecond=0) 
        time_ago = datetime_now - timedelta(minutes=minute_ago)

        container_url = phantom.build_phantom_rest_url("container")
        filtered_container_url = f"{container_url}?page_size=0&_filter_container_type=\"case\"&_filter_custom_fields__assignment_group=\"CSOC MDR Team\"&_filter_container_update_time__gte=\"{time_ago}\"&_exclude_custom_fields__servicenow_case_id=\"\""
        
        phantom.debug(f"Query URL:\n {filtered_container_url}")
        response = phantom.requests.get(
                filtered_container_url,
                verify=False
        )        
        response_code = response.status_code
        phantom.debug(f"Response code:\n {response_code}")
        
        response_json = response.json()
        phantom.debug(f"Raw response:\n{response_json}")

        if response.ok:
            data = response_json.get("data", [])
        else:
            success = False
            error = response_json.get("message", "Unknown error")
            error_msg = f"HTTP Request failed with status code {response_code}. error: {error})"

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
