def update_phantom_case(container_input=None, updating_info=None, **kwargs):
    """
    Update Phantom case
    
    Args:
        container_input: Phantom container ID (integer) or Container object (dictionary)
        updating_info: updating field in dictionary from
    
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
            
        container_id = str(container.get("id", ""))
        ok, message = phantom.update(container, updating_info)
        if not ok:
            raise Exception(f"Failed to update field {updating_info} to container ID: {container_id}. error: {message}")
        data = {"phantom_case_id": container_id, "updated_data": updating_info}
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