def set_phantom_custom_field(container_input=None, field=None, value=None, **kwargs):
    """
    Set the container lastUpdateToServiceNow field
    
    Args:
        container_input (CEF type: phantom container id)
        field
        value
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime

    result = {}
    success = True
    data = ""
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
        if field not in container.get("custom_fields", {}):
            phantom.debug(f"There is no custom field {field} in container ID: {container_id}. an update may not be successful")
        
        phantom.debug(f"BEFORE update:\n {container}")
        ok, message = phantom.update(container, {"custom_fields": {field: value}})
        if not ok:
            raise Exception(f"Failed to update custom field {field} to container ID: {container_id}. error: {message}")
        data = f"Container ID {container_id}. custom field {field} has been set to {value}."
        phantom.debug(f"AFTER update:\n {container}")
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

