def Update_containder_local(Container_id=None, a_status=None, Custom_fieldname=None, **kwargs):
    """
    set custom field last_automated_action
    
    Args:
        Container_id (CEF type: phantom container id)
        a_status
        Custom_fieldname
    
    Returns a JSON-serializable object that implements the configured data paths:
        res
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    update_dict = {}
    phantom.debug(Container_id)
    if isinstance(Container_id[0], int):
        container = phantom.get_container(Container_id[0])
    elif isinstance(Container_id[0], dict):
        container = Container_id[0]
    else:
        raise TypeError("container_input is neither a int or a dictionary")
    
    if a_status:
       # update_dict['custom_fields']['Last_Automated_Action'] = a_status[0]
        update_dict = {'custom_fields':{Custom_fieldname:  a_status[0]}}
      
    
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
