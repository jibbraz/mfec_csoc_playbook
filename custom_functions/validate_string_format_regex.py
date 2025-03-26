def validate_string_format_regex(regex=None, txt=None, **kwargs):
    """
    Validate string format by a given regular expression.
    
    Args:
        regex (CEF type: *)
        txt (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    # Write your custom code here...
    match = False
    # compiling the pattern for a given regex string
    pat = re.compile(r"{}".format(regex))
    if re.fullmatch(pat, txt):
        match = True
    outputs['result'] = match
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
