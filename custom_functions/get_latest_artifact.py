def get_latest_artifact(container_input=None, **kwargs):
    """
    Return the newest artifact of the container (dict)
    
    Args:
        container_input
    
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

        container_id = container.get("id")
        artifact_data = phantom.collect2(container=container, datapath=['artifact:*.data'])
        phantom.debug(f"artifact list: {artifact_data}")
        try:
            latest_artifact = artifact_data[-1][-1]
        except IndexError:
            raise Exception(f"There is no artifact in container ID: {container_id}. skipping...")
        
        data = latest_artifact
        
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