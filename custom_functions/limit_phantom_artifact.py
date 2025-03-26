def limit_phantom_artifact(container_input=None, maximum_artifact=None, artifact_name=None, **kwargs):
    """
    Delete all artifacts except the latest N artifacts and return the remaining
    
    Args:
        container_input: Phantom container ID (integer) or Container object (dictionary)
        maximum_artifact: Maximum amount of artifacts to be stored in the container
        artifact_name: name of artifact to limit (use * to ignore artifact name)
    
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
    data = []
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
        maximum_artifact = int(maximum_artifact)
        all_artifact = phantom.collect2(container=container, datapath=["artifact:*.id", "artifact:*.name"])
        
        if len(all_artifact) == 0:
            raise Exception(f"There is no artifact in container ID: {container_id}")
        
        filtered_artifact = [i for i in all_artifact if (str(i[1]) == str(artifact_name)) or (artifact_name == "*")]

        for artifact in filtered_artifact[:-maximum_artifact]:
            artifact_id = artifact[0]
            phantom.delete_artifact(artifact_id=artifact_id)
        
        phantom.debug(f"Clean artifact name {artifact_name} successfully for container id: {container_id}")
        data += [i[0] for i in phantom.collect2(container=container, datapath=['artifact:*.id'])]

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