def SET_TAG_QUAR(container_id_now=None, artifact_id_now=None, **kwargs):
    """
    device_quarantined
    
    Args:
        container_id_now (CEF type: phantom container id)
        artifact_id_now (CEF type: phantom artifact id)
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
