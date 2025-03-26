def ADD_IOC_Containment_LIST(input_IOC=None, IOC_Type=None, Container_id=None, **kwargs):
    """
    Args:
        input_IOC
        IOC_Type
        Container_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    outputs = []
    custom_list = phantom.get_list(list_name="Containment_List")
    list_item = list(custom_list[2:])
    list_item = list_item[0]
    #phantom.debug("print list\n")
    
    #phantom.debug(list_item)
    Add = [input_IOC,IOC_Type,str(Container_id)]
    #phantom.debug("ADD item {}".format(Add))
    #phantom.debug(type(list_item))
    if [input_IOC,IOC_Type,str(Container_id)] in list_item :
   # if ['10.10.10.12', 'ip', '1'] in list_item :
        phantom.debug("items already existis in list")
        outputs.append({'Results': "Exists"})
    else:
        phantom.add_list(list_name="Containment_List", values=[input_IOC,IOC_Type,Container_id])
        phantom.debug("Add IOC={0},TYPE={1},From eventid = {2}".format(input_IOC,IOC_Type,Container_id))
        outputs.append({'Results': "Success"})
    ''' custom_list = [item[0],item[1] for item in custom_list]
    for var in input_url:
        if var:
            parsed_url = urlparse.urlparse(input_url)
            if parsed_url.netloc not in custom_list:
                outputs.append({'filtered_url': var})
                
    '''
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(outputs)
    return outputs