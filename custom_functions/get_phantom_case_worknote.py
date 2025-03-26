def get_phantom_case_worknote(container_input=None, **kwargs):
    """
    Get Container notes and return container note list. container note sorted by note id
    
    Args:
        container_input: container id (integer) or container object (dictionary)
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################

    import json
    import phantom.rules as phantom
    from collections import defaultdict
    
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

        container_id = container.get("id")
        if (container_id == None) or (container_id == ""):
            raise Exception("Container ID not found")

#        container_note = [i.get("data") for i in phantom.get_notes(container=container) if i.get("success") == True]
#        container_note = sorted(container_note, key=lambda k: (k["id"]))
#        data = container_note
        
        note_url = phantom.build_phantom_rest_url("note")
        filtered_note_url = f"{note_url}?page_size=0&_filter_container={container_id}"
        response = phantom.requests.get(
            filtered_note_url,
            verify=False
        )        
        response_code = response.status_code
        phantom.debug(f"Response code:\n {response_code}")
        
        response_json = response.json()
        phantom.debug(f"Raw response:\n{response_json}")

        if response.ok:
            container_note = response_json.get("data", [])
            container_note = sorted(container_note, key=lambda k: (k["id"]))
            data = container_note
        else:
            success = False
            error = response_json.get("message", "Unknown error")
            error_msg = f"HTTP Request failed with status code {response_code}. error: {error})"

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg

    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result
