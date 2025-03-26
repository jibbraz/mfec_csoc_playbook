def test_update_ar(artifact_id=None, cef_field=None, cef_value=None, cef_data_type=None, container=None, **kwargs):
    """
    Update an artifact with the specified attributes. All parameters are optional, except that cef_field and cef_value must both be provided if one is provided.
    
    Args:
        artifact_id (CEF type: phantom artifact id): ID of the artifact to update, which is required.
        cef_field: The name of the CEF field to populate in the artifact, such as "destinationAddress" or "sourceDnsDomain". Required only if cef_value is provided.
        cef_value (CEF type: *): The value of the CEF field to populate in the artifact, such as the IP address, domain name, or file hash. Required only if cef_field is provided.
        cef_data_type: The CEF data type of the data in cef_value. For example, this could be "ip", "hash", or "domain". Optional, but only operational if cef_field is provided.
        container
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    updated_artifact = {}
    
    if not isinstance(artifact_id, int):
        raise TypeError("artifact_id is required")
    phantom.debug(container)
    artifacts = phantom.collect(container, 'artifacts:*', scope='all')
    phantom.debug(artifacts)
    # validate that if cef_field or cef_value is provided, the other is also provided
    if (cef_field and not cef_value) or (cef_value and not cef_field):
        raise ValueError("only one of cef_field and cef_value was provided")

    # cef_data should be formatted {cef_field: cef_value}
    for artifact in artifacts:
        if (artifact["id"] == artifact_id) :
            updated_artifact['cef'] = artifact['cef']
            updated_artifact['cef_types'] = artifact['cef_types']
            if cef_field:
               updated_artifact['cef'][cef_field] =  cef_value
            if cef_data_type and isinstance(cef_data_type, str):
               updated_artifact['cef_types'][cef_field] =  [cef_data_type]
    
    # separate tags by comma

    # now actually update the artifact
    phantom.debug('updating artifact {} with the following attributes:\n{}'.format(artifact_id, updated_artifact))
    url = phantom.build_phantom_rest_url('artifact', artifact_id)
    response = phantom.requests.post(url, json=updated_artifact, verify=False).json()

    phantom.debug('POST /rest/artifact returned the following response:\n{}'.format(response))
    if 'success' not in response or response['success'] != True:
        raise RuntimeError("POST /rest/artifact failed")

    return
