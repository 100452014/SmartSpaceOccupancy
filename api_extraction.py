import logging
import os
from datetime import date
from api_utilities import ingest_from_api_to_df_habitat, ingest_from_api_to_df_lenel, ingest_from_api_to_df_prodelfi

logging.basicConfig(level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper()))
logger: logging.RootLogger = logging.getLogger()

local_path = "PATH_TO_SAVE_EXTRACTED_FILES"


#########
#HABITAT#
#########
trigger_habitat = False

info_habitat = {'domain_id': 'HABITAT_DOMAIN',
                'client_id': 'HABITAT_CLIENT_ID',
                'client_secret': 'HABITAT_CLIENT_SECRET',
                'scope': 'HABITAT_SCOPE'}


# SPACES AND RESERVATIONS INFORMATION
params_habitat = ["habitat_spaces", "habitat_spacetypes", "habitat_floors", "habitat_buildings", "habitat_reservations"]
start_date = "2024-02-01T00:00:00"
end_date = "2024-02-01T23:59:59"
habitat_dates = [start_date, end_date]

if trigger_habitat:
    for entity in params_habitat:
        habitat_df = ingest_from_api_to_df_habitat(info_habitat, entity, logger, habitat_dates)
        file = f"{entity}_{start_date.replace(':', '').replace('-', '').replace('T', '')}.csv"
        habitat_df.to_csv(f"{local_path}habitat/{file}")
        logger.info(f"Results saved in file {file}")


#######
#LENEL#
#######
trigger_lenel = False

info_lenel = {'host': 'LENEL_HOST',
              'port': 'LENEL_PORT',
              'pem_path': f'{local_path}NAME_PEM_FILE',
              'application_id': 'LENEL_APP_ID',
              'user_name': 'LENEL_USER',
              'password': 'LENEL_PWD',
              'version': 'LENEL_VERSION'}

# EVENTS (ACCESSES) AND CARDHOLDERS
start_date = "2024-02-01T00:00:00"
end_date = "2024-02-01T23:59:59"
params_lenel = ["loggedevents", "cardholders"]

if trigger_lenel:
    for entity in params_lenel:
        lenel_df = ingest_from_api_to_df_lenel(info_lenel, entity, logger, start_date, end_date)
        file = f"lenel_{entity}_{start_date.replace(':', '').replace('-', '').replace('T', '')}.csv"
        lenel_df.to_csv(f"{local_path}lenel/{file}")
        logger.info(f"Results saved in file {file}")


##########
#PRODELFI#
##########
trigger_prodelfi = False

info_prodelfi = {'dominio': 'PRODELFI_DOMAIN',
                 'site': 'PRODELFI_SITE',
                 'serviciojson': 'PRODELFI_SERVICEJSON',
                 'metodo_movimiento': 'MOVIMIENTOSTARJETA_METHOD',
                 'clave': 'PRODELFI_KEY'}

entity = 'movimientostarjeta'
fec_inicio = "2024-02-02 12:00:00"
fec_final = "2024-02-02 18:00:00"

if trigger_prodelfi:
    prodelfi_df = ingest_from_api_to_df_prodelfi(info_prodelfi, entity, logger, fec_inicio, fec_final)
    file = f"prodelfi_{entity}_{date.today().strftime('%Y%m%d%H%M%S')}.csv"
    prodelfi_df.to_csv(f"{local_path}prodelfi/{file}")
    logger.info(f"Results saved in file {file}")

