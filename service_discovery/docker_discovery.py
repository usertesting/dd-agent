# std
import re
from os import path

import logging
import simplejson as json

# project
from utils.dockerutil import get_client as get_docker_client


log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5
PLACEHOLDER_REGEX = re.compile(r'%%.+?%%')


def _get_host(container_inspect):
    """Extract the host IP from a docker inspect object."""
    return container_inspect['NetworkSettings']['IPAddress']


def _get_port(container_inspect):
    """Extract the port from a docker inspect object."""
    return container_inspect['NetworkSettings']['Ports'].keys()[0].split("/")[0]


def _get_explicit_variable(container_inspect, var):
    """Extract the value of a config variable from env variables or docker labels.
       Return None if the variable is not found."""
    conf = _get_config_space(container_inspect['Config'])
    if conf is not None:
        return conf.get(var)

IMAGE_AND_CHECK = [
    ('redis', 'redisdb'),
    ('nginx', 'nginx'),
    ('mongo', 'mongo'),
]


VAR_MAPPING = {
    'host': _get_host,
    'port': _get_port,
}


def _get_etcd_check_tpl(prefix, key, **kwargs):
    """Retrieve template config strings from etcd."""
    from utils.etcdutil import get_client as get_etcd_client
    etcd_client = get_etcd_client()
    try:
        init_config_tpl = etcd_client.read(
            path.join(prefix, key, 'init_config'),
            timeout=kwargs.get('timeout', DEFAULT_TIMEOUT)).value
        instance_tpl = etcd_client.read(
            path.join(prefix, key, 'instance'),
            timeout=kwargs.get('timeout', DEFAULT_TIMEOUT)).value
        template = [init_config_tpl, instance_tpl]
    except:
        log.error('Fetching the value for {0} in etcd failed, auto-config for this check failed.'.format(key))
        return None
    return template


def _get_template_config(agentConfig, config_key, auto_config=False):
    """Extract a template config from a K/V store and returns it as a dict object."""
    # TODO: add more backends
    if agentConfig.get('sd_backend') == 'etcd':
        if auto_config is True:
            prefix = agentConfig.get('sd_autoconfig_dir')
        else:
            prefix = agentConfig.get('sd_template_dir')
        etcd_tpl = _get_etcd_check_tpl(prefix, config_key)
        if etcd_tpl is not None and len(etcd_tpl) == 2 and all(etcd_tpl):
            init_config_tpl, instance_tpl = etcd_tpl
        else:
            return None
    try:
        # build a list of all variables to replace in the template
        variables = PLACEHOLDER_REGEX.findall(init_config_tpl) + PLACEHOLDER_REGEX.findall(instance_tpl)
        variables = map(lambda x: x.strip('%'), variables)
        init_config_tpl = json.loads(init_config_tpl)
        instance_tpl = json.loads(instance_tpl)
    except json.JSONDecodeError:
        log.error('Failed to decode the JSON template fetched from {0}.'
                  'Auto-config for {1} failed.'.format(agentConfig.get('sd_backend'), config_key))
        return None
    return [init_config_tpl, instance_tpl, variables]


def _render_template(init_config_tpl, instance_tpl, variables):
    """Replace placeholders in a template with the proper values.
       Return a list made of `init_config` and `instances`."""
    config = [init_config_tpl, instance_tpl]
    for tpl in config:
        for key in tpl:
            for var in PLACEHOLDER_REGEX.findall(str(tpl[key])):
                if var.strip('%') in variables and variables[var.strip('%')]:
                    tpl[key] = tpl[key].replace(var, variables[var.strip('%')])
                else:
                    log.warning('Failed to find a value for the {0} parameter.'
                                ' The check might not be configured properly.'.format(key))
                    tpl[key].replace(var, '')
    # put the `instance` config in a list to respect the `instances` format
    config[1] = [config[1]]
    return config


def _get_check_config(agentConfig, docker_client, c_id, config_key=None):
    """Retrieve a configuration template and fill it with data pulled from docker."""
    inspect = docker_client.inspect_container(c_id)
    auto_config = config_key is None
    if config_key is None:
        image_name = inspect['Config']['Image']
        for image, check in IMAGE_AND_CHECK:
            if image == image_name:
                config_key = check
                break
    template_config = _get_template_config(agentConfig, config_key, auto_config=auto_config)
    if template_config is None:
        return None
    init_config_tpl, instance_tpl, variables = template_config
    var_values = {}
    for v in variables:
        if v in VAR_MAPPING:
            var_values[v] = VAR_MAPPING[v](inspect)
        else:
            var_values[v] = _get_explicit_variable(inspect, v)
    init_config, instances = _render_template(init_config_tpl, instance_tpl, var_values)
    return (config_key, init_config, instances)


def _get_config_space(container_conf):
    """Check whether the user config was provided through env variables or container labels.
       Return this config after removing its `datadog_` prefix."""
    env_variables = {v.split("=")[0].split("datadog_")[1]: v.split("=")[1] for v in container_conf['Env'] if v.split("=")[0].startswith("datadog_")}
    labels = {k.split('datadog_')[1]: v for k, v in container_conf['Labels'].iteritems() if k.startswith("datadog_")}

    if "check_name" in env_variables:
        return env_variables
    elif 'check_name' in labels:
        return labels
    else:
        return None


def get_configs(agentConfig):
    """Get the config for all docker containers running on the host."""
    docker_client = get_docker_client()
    # TODO: handle containers with the same image (create multiple instances in the check config)
    containers = [(container.get('Image').split(':')[0], container.get('Id'), container.get('Labels')) for container in docker_client.containers()]
    check_name, configs = None, {}

    for image, cid, labels in containers:
        # first, let's check if the labels specify a config key
        config_key = labels.get('datadog_config_key')
        check_name = labels.get('datadog_check_name')
        if config_key:
            conf = _get_check_config(agentConfig, docker_client, cid, config_key)
        elif image in [elem[0] for elem in IMAGE_AND_CHECK]:
            log.info(
                'datadog_config_key not found for container {0}, attempting auto-configuration.'.format(cid))
            conf = _get_check_config(agentConfig, docker_client, cid)
        else:
            log.warning('Container {0} was not recognized by auto-config, leaving it alone.'.format(cid))
            conf = None
        if conf is not None:
            check_name = check_name if check_name is not None else conf[0]
            configs[check_name] = (conf[1], conf[2])

    return configs
