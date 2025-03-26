def add_phantom_note(container_input=None, title=None, content=None, **kwargs):
    """
    Add note to Phantom container
    
    Args:
        container_input (CEF type: phantom container id)
        title: Title of note to add
        content: Content of note to add
    
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
        title = str(title)
        content = str(content)
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
        ok, message, note_id = phantom.add_note(container=container, title=title, content=content, note_type="general")

        if not ok:
            raise Exception(f"Failed to add note to container ID: {container_id}. error: {message}")
        phantom.debug(f"Container ID {container_id}. Added note ID {note_id} with title {title} and content {content}.")
        data["phantom_case_id"] = container_id
        data["note_id"] = note_id
        data["title"] = title
        data["content"] = content

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