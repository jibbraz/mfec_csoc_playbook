def merge_url_result(resultList=None, artifactInfo=None, **kwargs):
    """
    Update CEF containResult=True/False
    
    Args:
        resultList (CEF type: *)
        artifactInfo (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    # Write your custom code here...
    temp = resultList.replace('\n',"")
    temp = temp[:-2] + ']'
    resultJSON = json.loads(temp)
    
    artifactInfo = artifactInfo.replace("'","\"")
    artifactInfo = artifactInfo.replace("\n","")
    artifactInfo = artifactInfo[:-2] + ']'
    artifactInfoJSON = json.loads(artifactInfo)

    
    uniqueResult = { each['result_body']['url'] : each for each in resultJSON }.values()
    
    phantom.debug(uniqueResult) #dedup artifact id
    
    failList = []
    failDict = {}
    successList = []
    successDict = {}
    
    #copy unique list from artifact id for later processing
    for u in uniqueResult:
        successList.append(u['result_body']['url'])
            
    for u in uniqueResult:
        for r in resultJSON: 
            if u['result_body']['url'] == r['result_body']['url']:
                #phantom.debug('u url {}  :  r url {}'.format(u['result_body']['url'],r['result_body']['url'] ))
                if r['status'] != "success": 
                    phantom.debug('r status {}'.format(r['status']))
                    #failDict["artifact_id"] = u['artifact_id']
                    failList.append(u['result_body']['url']) #add failed artifact to failList 
                    #delete failed artifact from successList
                    successList.remove(u['result_body']['url'])
                    #phantom.debug("successList {}".format(successList)) #list of artifact id in case succuess to block
                    #phantom.debug("failList {}".format(failList)) #list of artifact id in case fail to block
                    break
                    
    #phantom.debug(resultJSON) #block url status on device
    #phantom.debug(uniqueResult) #dedup artifact id
    #phantom.debug("artifactInfoJSON {}".format(artifactInfoJSON)) #information of artifact cef
    phantom.debug("successList {}".format(successList)) #list of artifact id in case succuess to block
    phantom.debug("failList {}".format(failList)) #list of artifact id in case fail to block
    
    regexURL = re.compile(r"\A(https?://)")
    
    for failArtifactURL in failList:
        for artInfo in artifactInfoJSON: 
            processedURL = regexURL.sub('',artInfo["cef"][0]["requestURL"])
            if failArtifactURL == processedURL:
                #prepare artifact to update
                updateArtifact = {}
                updateArtifact["cef"] = artInfo['cef'][0]
                updateArtifact["cef"]["requestURL_ContainResult"] = "False"
                
                phantom.debug('Update artifact id={} with following parameter : {}'.format(artInfo["artifact_id"],updateArtifact))
                
                #post update artifact
                url = phantom.build_phantom_rest_url('artifact', artInfo["artifact_id"])
                response = phantom.requests.post(url, json=updateArtifact, verify=False).json()
                phantom.debug('POST /rest/artifact returned the following response:\n{}'.format(response))
                if 'success' not in response or response['success'] != True:
                    raise RuntimeError("POST /rest/artifact failed")
    
    for successArtifactURL in successList:
        for artInfo in artifactInfoJSON:
            processedURL = regexURL.sub('',artInfo["cef"][0]["requestURL"])
            if successArtifactURL == processedURL:
                updateArtifact = {}
                updateArtifact["cef"] = artInfo['cef'][0]
                updateArtifact["cef"]["requestURL_ContainResult"] = "True"
                
                phantom.debug('Update artifact id={} with following parameter : {}'.format(artInfo["artifact_id"],updateArtifact))
                
                #post update artifact
                url = phantom.build_phantom_rest_url('artifact', artInfo["artifact_id"])
                response = phantom.requests.post(url, json=updateArtifact, verify=False).json()
                phantom.debug('POST /rest/artifact returned the following response:\n{}'.format(response))
                if 'success' not in response or response['success'] != True:
                    raise RuntimeError("POST /rest/artifact failed")

    
    outputs = json.dumps(outputs)
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
