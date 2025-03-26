def Read_Results(results=None, **kwargs):
    """
    Args:
        results (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        output (CEF type: *): output
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    #phantom.debug(results);
    res1=[];
    res2=[];
    for action in results[0]:
        phantom.debug("naja")
        phantom.debug(action)
        sres={"action":action["action"],"app":action["app"],"asset":action["asset"],"status":action["status"],"message":action["message"]}
        if (action["status"] == "success"):
          res1.append(sres)
        elif(action["status"] == "failed"):
          res2.append(sres)
        
    phantom.debug("test")    
    phantom.debug(res1)

    phantom.debug("test")
    phantom.debug(res2)
    outputs = {"success":res1 , "failure":res2}
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(outputs)
    return outputs
