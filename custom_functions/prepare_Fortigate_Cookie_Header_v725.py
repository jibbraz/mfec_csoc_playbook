def prepare_Fortigate_Cookie_Header_v725(Cookies=None, **kwargs):
    """
    extract X-CSRF Token from cookie for Fortigate Session based authentication
    
    Args:
        Cookies (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        header (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import requests
    
    outputs = {}
    
    # Write your custom code here..
    phantom.debug("Cookie before process")
    phantom.debug(Cookies[0])
    
    dumpCookies = json.dumps(Cookies)
    temp = dumpCookies.split(',')
    
    phantom.debug("After split")
    phantom.debug(temp)
    header={}
    for c in temp:
        if "ccsrftoken_443=" in c:
            temp2 = c.split(';')
            temp3 = temp2[0].split('=')
            phantom.debug("extracted ccsrftoken : {}".format(temp3[1]))
    
    header['Cookie'] = str(Cookies[0])
    header['X-CSRFTOKEN'] = temp3[1].replace("\\","").replace('"',"")
    
    #phantom.debug("display header json")
   # phantom.debug(header)
    
    #fix error about json parser
    tempx= json.dumps(header)
    outputs['header'] = tempx.replace("'",'"')
    #outputs['header'] = json.dumps(header)
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs