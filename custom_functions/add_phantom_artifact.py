def add_phantom_artifact(container_input=None, artifact=None, name=None, label=None, severity=None, **kwargs):
    """
    Add artifact to container
    
    Args:
        container_input: Phantom container ID (integer) or Container object (dictionary)
        artifact: artifact to add in JSON object or valid JSON string
        name: Name of artifact (default: Update)
        label: Label of artifact (default: events)
        severity: Label of artifact (default: Medium)
    
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
    
    if not name:
        name = "Update"
    if not label:
        label = "events"
    if not severity:
        severity = "Medium"
    
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
        ok, message, artifact_id = phantom.add_artifact(container=container,
                                        raw_data={},
                                        cef_data=artifact,
                                        label=label,
                                        name=name,
                                        severity=severity,
                                        identifier=artifact.get("sys_id"),
                                        artifact_type=None,
                                        run_automation=False
                                        )
        if not ok:
            raise Exception(f"Fail to add artifact to container ID: {container_id}. error: {message}")
        phantom.debug(f"Successfully add artifact to container ID: {container_id}")
        data["container_id"] = container_id
        data["artifact_id"] = artifact_id
        data["artifact_raw"] = artifact
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"

    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg

    assert json.dumps(result)
    phantom.debug(result)
    return result
