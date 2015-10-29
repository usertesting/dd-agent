# std
import re
from os import path

import logging
import simplejson as json

# project
from utils.dockerutil import get_client as get_docker_client


log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5
PLACEHOLDER_REGEX = re.compile(r'%%.+%%')


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
            path.join(prefix, key, 'template', 'init_config'),
            timeout=kwargs.get('timeout', DEFAULT_TIMEOUT)).value
        instance_tpl = etcd_client.read(
            path.join(prefix, key, 'template', 'instance'),
            timeout=kwargs.get('timeout', DEFAULT_TIMEOUT)).value
        variables = etcd_client.read(
            path.join(prefix, key, 'variables'),
            timeout=kwargs.get('timeout', DEFAULT_TIMEOUT)).value
        template = [init_config_tpl, instance_tpl, variables]
    except:
        log.error('Fetching the value for {0} in etcd failed, auto-config for this check failed.'.format(key))
        return None
    return template


def _get_template_config(agentConfig, check_name):
    """Extract a template config from a K/V store and returns it as a dict object."""
    # TODO: add more backends
    if agentConfig.get('sd_backend') == 'etcd':
        etcd_tpl = _get_etcd_check_tpl(agentConfig.get('sd_template_dir'), check_name)
        if etcd_tpl is not None and len(etcd_tpl) == 3 and all(etcd_tpl):
            init_config_tpl, instance_tpl, variables = etcd_tpl
        else:
            return None
    try:
        init_config_tpl = json.loads(init_config_tpl)
        instance_tpl = json.loads(instance_tpl)
        variables = json.loads(variables)
    except json.JSONDecodeError:
        log.error('Failed to decode the JSON template fetched from {0}.'
                  'Auto-config for {1} failed.'.format(agentConfig.get('sd_backend'), check_name))
        return None
    return [init_config_tpl, instance_tpl, variables]


def _render_template(init_config_tpl, instance_tpl, variables):
    """Replace placeholders in a template with the proper values.
       Return a list made of `init_config` and `instances`."""
    config = [init_config_tpl, instance_tpl]
    for tpl in config:
        for key in tpl:
            if key in variables and PLACEHOLDER_REGEX.match(tpl[key]):
                tpl[key] = variables[key]
            else:
                log.warning('Failed to find a value for the {0} parameter.'
                            ' The check might not be configured properly.'.format(key))
                tpl[key] = ''
    # put the `instance` config in a list to respect the `instances` format
    config[1] = [config[1]]
    return config


def _get_check_config(agentConfig, docker_client, c_id):
    """Create a base config for simple checks from a template and data pulled from docker."""
    inspect = docker_client.inspect_container(c_id)
    image_name = inspect['Config']['Image']
    for image, check in IMAGE_AND_CHECK:
        if image == image_name:
            check_name = check
            break
    template_config = _get_template_config(agentConfig, check_name)
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
    return (check_name, init_config, instances)


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


def _get_default_config(docker_client, c_id):
    """Get a config stored in env variables or container labels for a container."""
    check_name = None
    init_config, instances = None, None
    conf = _get_config_space(docker_client.inspect_container(c_id)['Config'])
    if conf is None:
        log.warning('No default config was found for the container %s' % c_id)
        return None
    check_name = conf["check_name"]
    del conf["check_name"]

    if "init_config" in conf:
        init_config = json.loads(conf["init_config"])
        del conf["init_config"]

    if "instance" in conf:
        instances = [json.loads(conf["instance"])]
    else:
        instances = [{k: v} for k, v in conf.iteritems()]

    return (check_name, init_config, instances)


def get_configs(agentConfig):
    """Get the config for all docker containers running on the host."""
    docker_client = get_docker_client()
    # TODO: handle containers with the same image (create multiple instances in the check config)
    containers = [(container.get('Image').split(':')[0], container.get('Id')) for container in docker_client.containers()]
    configs = {}

    for image, cid in containers:
        if image in [elem[0] for elem in IMAGE_AND_CHECK]:
            conf = _get_check_config(agentConfig, docker_client, cid)
        else:
            conf = _get_default_config(docker_client, cid)
        if conf is not None:
            configs[conf[0]] = (conf[1], conf[2])

    return configs
