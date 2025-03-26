def checkExistingObject(URL=None, **kwargs):
    """
    Check that object already created
    
    Args:
        URL (CEF type: url)
    
    Returns a JSON-serializable object that implements the configured data paths:
        status (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug(URL)
    response = phantom.requests.get(URL, verify=False).json()
        
    phantom.debug('GET returned the following response:\n{}'.format(response))
    if 'success' in response or response['success'] == True:
        phantom.debug('Object following URL already exists.\n Do not create object this time.')
        phantom.debug(URL)
        outputs = 1
    else :
        phantom.debug('Object did not exists.\n Creating an object.')
        outputs = 0
    
    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
