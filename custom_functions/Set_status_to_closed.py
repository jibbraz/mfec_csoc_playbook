def Set_status_to_closed(container_id_now=None, **kwargs):
    """
    Args:
        container_id_now (CEF type: phantom container id)
    
    Returns a JSON-serializable object that implements the configured data paths:
        output (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json, requests
    import phantom.rules as phantom

    url_con = "https://127.0.0.1/rest/container/" + str(container_id_now)
    headers = {
       'ph-auth-token': 'BM9+Ldo1CGrveMzCnn0UcnK0Nl5iuJUcTPAWKT4Vhjk=',
       'Content-Type': 'application/json'
    }

    payload = json.dumps(
                {
                    "status": "closed"
                })
    res_con = requests.request("POST", url_con, data=payload, headers=headers, verify=False)
    return res_con.text

