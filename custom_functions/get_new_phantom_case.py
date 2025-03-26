def get_new_phantom_case(start_datetime=None, minute_ago=None, **kwargs):
    """
    Return list of new phantom cases.
    start_datetime = filter only the case created after this time
    minute_ago = amount of minutes ago to determine whether the case is new. Check with container_update_time
    
    Args:
        start_datetime: filter only the case created after this time
        minute_ago: amount of minutes ago to determine whether the case is new. Check with container_updated_time
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime, timedelta

    
    result = {}
    success = True
    data = []
    error_msg = ""
    
    try:
        if not (str(minute_ago).isdigit()):
            raise Exception("minute_ago is not a number")
            
        minute_ago = int(minute_ago)
        
        if isinstance(start_datetime, str):
            start_datetime = datetime.strptime(start_datetime, "%d/%m/%Y %H:%M:%S")
        elif isinstance(start_datetime, datetime):
            start_datetime = start_datetime
        else:
            raise Exception("Incorrect start_datetime format. correct format example: 31/12/2023 07:00:00")
        
        datetime_now = datetime.now().replace(microsecond=0)
        time_ago = datetime_now - timedelta(minutes=minute_ago)

        container_url = phantom.build_phantom_rest_url('container')
        filtered_container_url = f"{container_url}?page_size=0&_filter_container_type=\"case\"&_filter=(create_time__gte=\"{time_ago}\" OR container_update_time__gte=\"{time_ago}\")&_filter_custom_fields__servicenow_case_id=\"\"&_filter_custom_fields__create_on_servicenow=\"Yes\"&_exclude_create_time__lte=\"{start_datetime}\""
        
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
