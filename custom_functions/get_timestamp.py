def get_timestamp(**kwargs):
    """
    Return current date and time in format dd/mm/yyyy HH:MM:SS (i.e. 01/01/2024 08:05:01)
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime
    import pytz
    
    result = {}
    success = True
    data = ""
    error_msg = ""
    try:
        tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(tz)
#        now = datetime.now()
        now_str = now.strftime("%d/%m/%Y %H:%M:%S")
        data = now_str
    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"
    
    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    
    # Return a JSON-serializable object
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result
