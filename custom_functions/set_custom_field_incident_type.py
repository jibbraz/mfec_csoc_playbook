def set_custom_field_incident_type(Container_id=None, incident_type=None, **kwargs):
    """
    set custom field "Incident Type"
    
    Args:
        Container_id (CEF type: phantom container id)
        incident_type
    
    Returns a JSON-serializable object that implements the configured data paths:
        res
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    update_dict = {}
    phantom.debug(Container_id)
    if isinstance(Container_id[0], int):
        container = phantom.get_container(Container_id[0])
    elif isinstance(Container_id[0], dict):
        container = Container_id[0]
    else:
        raise TypeError("container_input is neither a int or a dictionary")
    
    if incident_type:
        update_dict = {'custom_fields':{'Incident Type':  incident_type[0]}}
    
    #phantom.debug(update_dict)
    
    if update_dict:
        phantom.debug('Updating container {0} with the following information: "{1}"'.format(container['id'], update_dict))
        success, message = phantom.update(container,  update_dict)
    else:
        phantom.debug("Valid container entered but no valid container changes provided.")
        
    phantom.debug("status = {}".format(success))
    # Return a JSON-serializable object
   # phantom.debug(success)
    #phantom.debug(message)
  #  container = phantom.get_container(Container_id[0])
   # phantom.debug(container)   
   # assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return success
    
  
