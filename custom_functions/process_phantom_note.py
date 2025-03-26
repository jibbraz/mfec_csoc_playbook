def process_phantom_note(raw_phantom_note=None, add_text=None, **kwargs):
    """
    Extract and process Phantom work notes from Phantom API response to usable format
    
    Args:
        raw_phantom_note: Phantom container note list in RAW format
        add_text: Text to add to note content which indicate that this note is from Phantom
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime
    from dateutil import parser
    import pytz

    result = {}
    success = True
    data = []
    error_msg = ""
    tz = pytz.timezone('Asia/Bangkok')
    
    try:
        formatted_list = []
        for note in raw_phantom_note:
            title = note.get("title", "")
            content = note.get("content", "").replace("\n", "\r\n")
            content += f"\r\n{add_text}"
            author = note.get("author", "")
            container_id = note.get("container", "")
            container = phantom.get_container(container_id)
            servicenow_case_id = container.get("custom_fields", {}).get("servicenow_case_id", "")
#            creation_date = note.get("create_time", "")
            creation_date = note.get("modified_time", "")
#            creation_date = parser.parse(creation_date)
            creation_date = parser.parse(creation_date).astimezone(tz)
            creation_date = creation_date.strftime("%d/%m/%Y %H:%M:%S")
            
            formatted_note = {
                "title": title,
                "creation_date": creation_date,
                "phantom_case_id": container_id,
                "servicenow_case_id": servicenow_case_id,
                "author": author,
                "content": content,
                "raw_version": note
            }
            
            data.append({"note_info": formatted_note})
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