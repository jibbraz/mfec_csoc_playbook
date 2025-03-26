def debug_variable(var1=None, var2_list=None, **kwargs):
    """
    Args:
        var1 (CEF type: *)
        var2_list (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug("debug item type.....")
    phantom.debug(var1)
    
    phantom.debug("debug list type.....")
    phantom.debug(var2_list)
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
