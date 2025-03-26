def strip_url_prefix(requestURLs=None, **kwargs):
    """
    Strip "http://" and "https://" from input string
    
    Args:
        requestURLs (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        processedURL (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug('custom function called')
    
    phantom.debug(requestURLs)
    listURL = requestURLs.split(', ')
    
    processedList = []
    regexURL = re.compile(r"\A(https?://)")
    
    for requestURL in listURL:
        dbugMessage = "URL from aftifact.requestURL : "+requestURL
        phantom.debug(dbugMessage)
        #processedURL = requestURL.strip("http://").strip("https://")
        processedURL = regexURL.sub('',requestURL)
        dbugMessage = "URL after regex-sub : "+processedURL
        phantom.debug(dbugMessage)
        
        processedRecord = dict()
        processedRecord["url"] = processedURL
        processedRecord["action"] = 1
        processedRecord["status"] = 1
        processedRecord["type"] = 0
        phantom.debug(processedRecord)
        processedList.append(processedRecord)
        #processedList.append(processedURL)
    
    #outputs = {'processedURL': processedURL}
    outputs = json.dumps(processedList)
    phantom.debug(outputs)
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
