def sort_and_gen_markdown(resultList=None, **kwargs):
    """
    Args:
        resultList (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        markdown (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    resultList = resultList.replace("\n","")
    resultList = resultList[:-2] + ']'
    resultJSON = json.loads(resultList)
    #phantom.debug(resultJSON)
    
    uniqueDeviceList = []
    uniqueURLList = []
    
    for result in resultJSON:
        device = result["device"]
        url = result["body"]["url"]
        if device not in uniqueDeviceList:
            uniqueDeviceList.append(device)
        if url not in uniqueURLList:
            uniqueURLList.append(url)
    
    #phantom.debug(uniqueDeviceList)
    #phantom.debug(uniqueURLList)
    
    header = "| **Blocking URL** |"
    for uniqueDevice in uniqueDeviceList :
        header = header +" **{}** |".format(uniqueDevice)
    header = header +"\n| ----------- |"
    for uniqueDevice in uniqueDeviceList :
        header = header +" ----------- |"
    
    #phantom.debug(header)
    
    markdownHeader = """| **Blocking URL** | **DC1-ATP-Seg-1** | **DC2-ATP-Seg-2** | **DR1-ATP-Seg-1** | **DR2-ATP-Seg-1** |**DR2-ATP-Seg-2**|
    | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
    """
    markdownBody = ""
    markdownLine = ""

    for uniqueURL in uniqueURLList: 
        markdownLine = markdownLine + "| {} |".format(uniqueURL)
        for uniqueDevice in uniqueDeviceList: 
            for result in resultJSON:
                result_device = result["device"]
                result_url = result["body"]["url"]
                result_status = result["status"]
                result_code = result["code"]
                result_reason = result["reason"]
                if uniqueDevice == result_device and uniqueURL == result_url: 
                    if result_status == "success":
                        markdownLine = markdownLine + " {} |".format(result_status)
                    else:
                        markdownLine = markdownLine + "{}:{}|".format(result_status,result_code)
                        #markdownLine = markdownLine + "{}:{}:{}|".format(result_status,result_code,result_reason)
                    break
                    #markdownBody.append(markdownLine)
        markdownLine = markdownLine + "\n"
    
    markdownBody = markdownHeader+markdownLine
    #phantom.debug(markdownBody)
    outputs = { "markdown": markdownBody }
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
