# 3rd party
from etcd import Client


DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 4001
DEFAULT_PROTOCOL = 'http'
DEFAULT_RECO = True

_etcd_client_settings = {"protocol": DEFAULT_PROTOCOL}


def get_etcd_settings():
    global _etcd_client_settings
    return _etcd_client_settings


def reset_etcd_settings():
    global _etcd_client_settings
    _etcd_client_settings = {"protocol": DEFAULT_PROTOCOL}


def set_etcd_settings(config):
    global _etcd_client_settings
    _etcd_client_settings = {
        'host': config.get('host', DEFAULT_HOST),
        'port': int(config.get('port', DEFAULT_PORT)),
        'allow_reconnect': config.get('allow_reconnect', DEFAULT_RECO),
        'protocol': config.get('protocol', DEFAULT_PROTOCOL),
    }


def get_client():
    return Client(**_etcd_client_settings)
