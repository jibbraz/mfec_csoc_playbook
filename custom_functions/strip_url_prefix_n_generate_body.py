def strip_url_prefix_n_generate_body(requestURLs=None, **kwargs):
    """
    Strip "http://" and "https://" from input string  and generate body request for add web override category on fortigate
    
    Args:
        requestURLs (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        bodyFormat (CEF type: *): processed URL in json body format
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug(requestURLs)
    regexURL = re.compile(r"\A(https?://)")
    processedURL = regexURL.sub('',requestURLs)
    dbugMessage = "URL after regex-sub : "+processedURL
    phantom.debug(dbugMessage)
    
    processedRecord = dict()
    processedRecord["url"] = processedURL
    processedRecord["status"] = "enable"
    processedRecord["rating"] = 26 #malicious site
    phantom.debug(processedRecord)
    outputs = json.dumps(processedRecord)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
