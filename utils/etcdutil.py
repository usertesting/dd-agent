# 3rd party
from etcd import Client


DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 4003
DEFAULT_PROTOCOL = 'https'
DEFAULT_RECO = True

_etcd_client_settings = {"protocol": DEFAULT_PROTOCOL}


def get_docker_settings():
    global _etcd_client_settings
    return _etcd_client_settings


def reset_docker_settings():
    global _etcd_client_settings
    _etcd_client_settings = {"protocol": DEFAULT_PROTOCOL}


def set_docker_settings(init_config, instance):
    global _etcd_client_settings
    _etcd_client_settings = {
        'host': init_config.get('host', DEFAULT_HOST),
        'port': instance.get('port', DEFAULT_PORT),
        'allow_reconnect': instance.get('allow_reconnect', DEFAULT_RECO),
        'protocol': instance.get('protocol', DEFAULT_PROTOCOL),
    }


def get_client():
    return Client(**_etcd_client_settings)
