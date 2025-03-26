def Set_Detection_Technology_Incident_Type(container_id=None, **kwargs):
    """
    Args:
        container_id (CEF type: phantom container id)
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    update_dict = {}
    phantom.debug(container_id)
    if isinstance(container_id, int):
        container = phantom.get_container(container_id)
    elif isinstance(container_id, dict):
        container = container_id[0]
    else:
        raise TypeError("container_input is neither a int or a dictionary")
    
    update_dict = {'custom_fields':{'Detection Technology':"Splunk ES"}}
    

    if update_dict:
        success, message = phantom.update(container,  update_dict)
    else:
        phantom.debug("Valid container entered but no valid container changes provided.")
        
    phantom.debug("status = {}".format(success))
    return success
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    