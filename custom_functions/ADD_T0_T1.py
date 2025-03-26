def ADD_T0_T1(container_id_now=None, **kwargs):
    """
    Set T0 default value
    
    Args:
        container_id_now (CEF type: phantom container id)
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json, requests, datetime, pytz

    class ADD_T0_T1:
        def __init__(self):
            self.headers = {
                'ph-auth-token': 'BM9+Ldo1CGrveMzCnn0UcnK0Nl5iuJUcTPAWKT4Vhjk=',
                'Content-Type': 'application/json'}
            self._base_url = 'https://127.0.0.1/rest/container'
            self.Timer_defined = {
                "T0": "create_time",
                "T1": "start_time"
            }
        def CF_PAYLOAD(self, cont_id):
            url_con = self._base_url + "/" + str(cont_id)
            res_con = requests.request("GET", url_con, headers=self.headers, verify=False)
            info_con = json.loads(res_con.text)
            url_sys = 'https://127.0.0.1/rest/system_info'
            res_sys = requests.request("GET", url_sys, headers=self.headers, verify=False)
            TZ_info = json.loads(res_sys.text).get('time_zone')
            GAP = pytz.timezone(TZ_info).localize(datetime.datetime.now()) - pytz.timezone('UTC').localize(datetime.datetime.now())
            timer_need_input = ['T' + str(num) for num in range(2) if info_con.get('custom_fields').get('T' + str(num)) in [None, '']]
            result = dict()
            for timer in timer_need_input:
                note = self.Timer_defined.get(timer)
                T_TZ = info_con.get(note)
                try:
                    T_UTC = datetime.datetime.strptime(T_TZ, "%Y-%m-%dT%H:%M:%S.%fZ")
                    T_timestamp = datetime.datetime.timestamp(T_UTC) - GAP.total_seconds()
                    T = datetime.datetime.fromtimestamp(T_timestamp)
                    if T is not None:
                        result[timer] = datetime.datetime.strftime(T ,"%Y-%m-%d %H:%M:%S")
                except:
                    print("!!! GET_TIME MODULE Failed To Excute For" + timer + "!!!")

            payload = json.dumps(
                {"custom_fields": result
                 })
            return payload

        def ACTION_POST(self ,cont_id):
            payload = self.CF_PAYLOAD(cont_id)
            url = self._base_url + "/" + str(cont_id)
            requests.request("POST", url, headers=self.headers, data=payload, verify=False)
            return
    ADD_ACTION= ADD_T0_T1()
    ADD_ACTION.ACTION_POST(container_id_now)
