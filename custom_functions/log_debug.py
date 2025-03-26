def log_debug(something=None, **kwargs):
    """
    print everything
    
    Args:
        something
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    phantom.debug(something)
    return
