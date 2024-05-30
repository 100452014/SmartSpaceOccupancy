import hashlib
import json
import logging
import os
import time

import pandas as pd
import requests

logging.basicConfig(level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper()))
logger: logging.RootLogger = logging.getLogger()


###########
##HABITAT##
###########


def get_token_habitat(info, logger):
    url = f"https://login.microsoftonline.com/{info['domain_id']}/oauth2/v2.0/token"
    payload = f"grant_type=client_credentials&client_id={info['client_id']}&client_secret={info['client_secret']}&scope={info['scope']}"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        logger.debug('Getting authorization token...')
        response = requests.request("POST", url, headers=headers, data=payload)
        logger.debug('Status code request: {}'.format(response.status_code))
        response.raise_for_status()
        logger.debug('Token obtained successfully')

    except Exception as e:
        raise Exception(e)

    token = response.json()['access_token']
    return token


def get_headers_habitat(info, logger):
    token = get_token_habitat(info, logger)
    headers = {'Authorization': f'Bearer {token}',
               'Content-type': 'application/json'
               }
    return headers


def clean_url_for_habitat(url):
    url = url.replace("%3A", ":").replace("%252B", "%2B").replace("%5B", "[").replace("%5D", "]").replace("%2F", "/")
    return url


def verify_response(original_response):
    status = original_response.status_code
    message = ""
    if original_response.status_code not in [200]:
        message = original_response.content
    return status, message


def get_response_habitat(info, logger, url, headers, url_params={}, pagination=False, response_result_key=None):
    from urllib import parse

    if pagination:
        page = 1
        response = []
        while True:
            url_params['page'] = page
            paginated_url = f"{url}?{parse.urlencode(url_params)}"
            paginated_url = clean_url_for_habitat(paginated_url)
            logger.info(f"Petición a {paginated_url}")
            original_response = requests.get(paginated_url, headers=headers, verify=False)
            status, message = verify_response(original_response)
            if status == 401:
                headers = get_headers_habitat(info, logger)
            elif status == 200:
                response_pagination = json.loads(original_response.content)
                # Reservas continuas tiene los resultados en la clave "reservations", todas las demas llamadas tienen los resultados directamente en la response
                if response_result_key is not None:
                    response_pagination = response_pagination[response_result_key]
                response.extend(response_pagination)
                if len(response_pagination) == 0:
                    break
                page = page + 1
            else:
                raise Exception(f"Failure with status {status} and message {message}")

        logger.info(f"Numero Resultados Totales: {len(response)}")
    else:
        if len(url_params.keys()) > 0:
            url = f"{url}?{parse.urlencode(url_params)}"
            url = clean_url_for_habitat(url)
        logger.info(f"Petición a {url}")
        while True:
            original_response = requests.get(url, headers=headers, verify=False)
            status, message = verify_response(original_response)
            if status == 401:
                headers = get_headers_habitat(info, logger)
            elif status == 200:
                response = json.loads(original_response.content)
                logger.info(f"Numero Resultados Totales: {len(response)}")
                break
            else:
                raise Exception(f"Failure with status {status} and message {message}")
    return response


def format_reservations(response):
    reservation_response = []
    for item in response:
        for space in item['spaces']:
            reservation_item = {'id': item['id'],
                                'owner': item['owner']['employeeNumber'],
                                'space': space['id'],
                                'status': item['status'],
                                'startDate': item['startDate'],
                                'endDate': item['endDate'],
                                'name': item['name'],
                                'description': item['description'],
                                'hidden': item['hidden']
                                }
            reservation_response.append(reservation_item)
    return reservation_response


def ingest_from_api_to_df_habitat(info: dict, entity: str, logger, dates=None):
    # define host
    host = 'https://mash.habitatworkspace.com'
    # define headers
    headers = get_headers_habitat(info, logger)

    # crea url y obtiene datos
    if entity == 'habitat_spaces':
        url = f"{host}/esite/api/v2/spaces"
        response = get_response_habitat(info, logger, url=url, headers=headers, pagination=True,
                                        url_params={'from': dates[0], 'to': dates[1], 'perPage': 100})

    elif entity == 'habitat_spacetypes':
        url = f"{host}/esite/api/v2/spaceTypes"
        response = get_response_habitat(info, logger, url=url, headers=headers, pagination=False,
                                        url_params={'from': dates[0], 'to': dates[1], 'perPage': 100})

    elif entity == 'habitat_floors':
        url = f"{host}/habitat/api/v2/floors"
        response = get_response_habitat(info, logger, url=url, headers=headers, pagination=False,
                                        url_params={'from': dates[0], 'to': dates[1], 'perPage': 100})

    elif entity == 'habitat_buildings':
        url = f"{host}/habitat/api/v2/buildings"
        response = get_response_habitat(info, logger, url=url, headers=headers, pagination=False,
                                        url_params={'from': dates[0], 'to': dates[1], 'perPage': 100})

    elif entity == 'habitat_cities':
        url = f"{host}/habitat/api/v2/cities"
        response = get_response_habitat(info, logger, url=url, headers=headers, pagination=True,
                                        url_params={'from': dates[0], 'to': dates[1], 'perPage': 100})

    elif entity == 'habitat_reservations':
        url = f"{host}/reservations/api/v1/reservations"
        for i in range(len(dates)):
            dates[i] += "%2B01:00[Europe/Madrid]"
        response = format_reservations(get_response_habitat(info, logger, url=url, headers=headers, pagination=True,
                                                            url_params={'from': dates[0], 'to': dates[1], 'perPage': 100}))

    else:
        raise Exception(f"Entity value {entity} not admitted")

    # converts response to pandas DataFrame
    df = pd.DataFrame(response)
    return df


#########
##LENEL##
#########


def request_api(info, method, url, payload, headers):
    """
      Executes de GET and POST request to an API.

      Includes retries if the API request does not return a 200 status code. If the retries exceed a maximum number
      of retries defined, fails.

      Parameters:
        info : Certificate for the API verification.
        method : Defines the method for the request: POST or GET.
        url : URL for the API request.
        payload : Body of the request.
        headers : Headers of the request.

      Return:
        Response (json)
    """

    max_retries = 3
    wait_time = 5
    retry = 0

    while True:

        logger.info(f"Requesting API with method {method}.")

        if method == 'POST':
            response = requests.post(url, headers=headers, data=payload, verify=info['pem_path'])
        elif method == 'GET':
            response = requests.get(url, headers=headers, data=payload, verify=info['pem_path'])
        else:
            raise Exception(f"\nNo se define un método válido para la llamada a la API.\nMétodo definido: {method}.\n"
                            f"Se fuerza el fallo de la tarea desde lenel_utilities.py.\n")

        if response.status_code == 200:
            logger.info(f"Request successfull.")
            response = response.json()
            break
        elif response.status_code == 401 and retry <= max_retries:
            logger.info(
                f"Request API with method {method}. Error {response.status_code} in API response. Refreshing token.")
            token, version, payload = get_token_lenel(info)
            continue
        elif 'item_list' not in response and retry <= max_retries:
            retry += 1
            logger.info(
                f"Request API with method {method}. Error {response.status_code} in API response, retry number {retry} will be executed after {wait_time} seconds.")
            time.sleep(wait_time)
            continue
        elif 'item_list' not in response and retry > max_retries:
            logger.info(
                f"Request API with method {method}. Error {response.status_code} in API response, number of retries exceeded.")
            response = None
            break
        else:
            logger.info(
                f"Request API with method {method} with unexpected resolution. Staus: {response.status_code}. Response: {response}")
            response = None
            break

    return response


def get_token_lenel(info, logger):
    payload = json.dumps({
        "user_name": info['user_name'],
        "password": info['password'],
        "application_id": info['application_id']
    })
    headers = {
        'Content-Type': 'application/json'
    }
    version = info['version']
    url = f"https://{info['host']}:{info['port']}/api/access/onguard/openaccess/authentication?version=" + version

    logger.info(f"Obtaining token.")
    response = requests.post(url, headers=headers, data=payload, verify=info['pem_path'])

    if response.status_code == 200:
        response = response.json()
        token = response.get("session_token", "")
        logger.info(f"Token generated")
    else:
        token = None
        version = None
        payload = None
        logger.info(f"The token generation has failed.")

    return token, version, payload


def get_response_lenel(info, param: str, logger, fec=None, fec_inicio=None):
    token, version, payload = get_token_lenel(info, logger)

    headers = {
        'Session-Token': token,
        'Content-Type': 'application/json'
    }
    method = "GET"
    mainlist = []

    try:
        if param == 'cardholders':
            url = f"https://{info['host']}:{info['port']}/api/access/onguard/openaccess/cardholders?filter=timestamp>='{fec_inicio}'ANDtimestamp<='{fec}'&version=" + version
            response = request_api(info, method, url, payload, headers)
            page_number = response['total_pages']

            for i in range(1, page_number + 1):
                url = f"https://{info['host']}:{info['port']}/api/access/onguard/openaccess/cardholders?filter=timestamp>='{fec_inicio}'ANDtimestamp<='{fec}'&page_number={i}&version=" + version
                response = request_api(info, method, url, payload, headers)['item_list']
                mainlist.extend(response)

        if param == 'loggedevents':
            url = f'https://{info["host"]}:{info["port"]}/api/access/onguard/openaccess/logged_events?filter=event_type<>30ANDevent_type<>4ANDevent_type<>11ANDtimestamp>="{fec_inicio}"ANDtimestamp<="{fec}"&version=' + version + "&page_size=100"
            print(url)
            response = request_api(info, method, url, payload, headers)
            page_number = response['total_pages']
            total_items = response['total_items']

            if 'item_list' not in response:
                mainlist = None

            else:
                logger.info(f"{total_items} will be processed, that correspond to {page_number} pages")
                for i in range(1, page_number + 1):
                    url = f'https://{info["host"]}:{info["port"]}/api/access/onguard/openaccess/logged_events?filter=event_type<>30ANDevent_type<>4ANDevent_type<>11ANDtimestamp>="{fec_inicio}"ANDtimestamp<="{fec}"&page_number={i}&version=' + version + "&page_size=100"
                    response = request_api(info, method, url, payload, headers)
                    page = response['item_list']
                    logger.info(f"{i} of {page_number} processed")
                    mainlist.extend(page)

    except Exception as e:
        raise Exception(e)

    return mainlist


def ingest_from_api_to_df_lenel(info: dict, param: str, logger, fec_inicio=None, fec_final=None):
    mainlist = get_response_lenel(info, param, logger, fec_final, fec_inicio)

    try:
        if param == 'cardholders':
            cardholder_list = []
            for element in mainlist:
                cardholder_list.append(element['property_value_map'])

        if param == 'loggedevents':
            list_logged_events = []
            logged_events = mainlist
            if mainlist == None:
                list_logged_events = []
            else:
                for element in logged_events:
                    list_logged_events.append(element)

    except Exception as e:
        raise Exception(f"Not valid entity {param}")

    if param == 'cardholders':
        df = pd.DataFrame.from_dict(cardholder_list)

    if param == 'loggedevents':
        df = pd.DataFrame.from_dict(list_logged_events)

    return df


############
##PRODELFI##
############


def create_signature(fec_i, fec_f, clave):
    prodelfi_empresa = "101"
    mensaje = prodelfi_empresa + fec_i + fec_f + clave
    m = hashlib.sha1()
    m.update(mensaje.encode('utf-8'))
    return m.hexdigest()


def request_api_prodelfi(url, headers, payload):
    response = requests.request("POST", url, headers=headers, data=payload)
    return response


def ingest_from_api_to_df_prodelfi(info, param, logger, fec_i=None, fec_f=None):
    prodelfi_empresa = "101"

    headers = {
        'Content-Type': 'application/json'
    }

    if param == 'movimientostarjeta':
        fec_i = fec_i[:10]
        fec_f = fec_f[:10]
        url = info['dominio'] + info['site'] + "/" + info['serviciojson'] + "/" + info['metodo_movimiento']

        signature = create_signature(fec_i, fec_f, info['clave'])
        payload = json.dumps({
            "Empresa": prodelfi_empresa,
            "FechaInicial": fec_i,
            "FechaFinal": fec_f,
            "Signature": signature
        })
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        response = response.json()

    else:
        raise Exception(f"Entity {param} not accepted")

    df = pd.DataFrame.from_dict(data=response, dtype=str)
    return df
