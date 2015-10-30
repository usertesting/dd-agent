# set up logging before importing any other components
if __name__ == '__main__':
    from config import initialize_logging  # noqa
    initialize_logging('dd-tcp-rtt')

# std
#import glob
import logging
#import os
import signal
import sys
#import time

# 3rd party
#import yaml

# datadog
from config import (
    DEFAULT_CHECK_FREQUENCY,
    get_confd_path,
    get_config,
    get_logging_config,
    PathNotFound,
)
from utils.platform import Platform
from utils.subprocess_output import subprocess

log = logging.getLogger('dd-tcp-rtt')

JAVA_LOGGING_LEVEL = {
    logging.CRITICAL: "FATAL",
    logging.DEBUG: "DEBUG",
    logging.ERROR: "ERROR",
    logging.FATAL: "FATAL",
    logging.INFO: "INFO",
    logging.WARN: "WARN",
    logging.WARNING: "WARN",
}


class DDTcpRtt(object):
    """
    Start dd_tcp-rtt if configured
    """
    def __init__(self, confd_path, agentConfig):
        self.confd_path = confd_path
        self.agentConfig = agentConfig
        self.logging_config = get_logging_config()
        self.check_frequency = DEFAULT_CHECK_FREQUENCY

    def terminate(self):
        self.dd_tcp_rtt.terminate()

    def _handle_sigterm(self, signum, frame):
        # Terminate jmx process on SIGTERM signal
        log.debug("Caught sigterm. Stopping subprocess.")
        self.dd_tcp_rtt.terminate()

    def register_signal_handlers(self):
        """
        Enable SIGTERM and SIGINT handlers
        """
        try:
            # Gracefully exit on sigterm
            signal.signal(signal.SIGTERM, self._handle_sigterm)

            # Handle Keyboard Interrupt
            signal.signal(signal.SIGINT, self._handle_sigterm)

        except ValueError:
            log.exception("Unable to register signal handlers.")

    def configure(self, checks_list=None, clean_status_file=True):
        """
        Instantiate DD-TCP-RTT parameters.
        """

        self.tcp_checks, self.invalid_checks,  = \
            self.get_configuration(self.confd_path, checks_list=checks_list)

    def should_run(self):
        """
        Should DDTcpRtt run ?
        """
        return True

    def run(self, command, checks_list=None, reporter=None, redirect_std_streams=False):
        """
        Run DDTcpRtt

        redirect_std_streams: if left to False, the stdout and stderr of DDTcpRtt are streamed
        directly to the environment's stdout and stderr and cannot be retrieved via python's
        sys.stdout and sys.stderr. Set to True to redirect these streams to python's sys.stdout
        and sys.stderr.
        """


        try:
            return self._start(command, reporter, redirect_std_streams)
        except Exception:
            log.exception("Error while initiating DDTcpRtt")
            raise

    @classmethod
    def get_configuration(cls, confd_path, checks_list=None):
        """
        Return a tuple ( invalid_checks )

        invalid_checks: dictionary whose keys are check names that are JMX checks but
        they have a bad configuration. Values of the dictionary are exceptions generated
        when checking the configuration
        """
        invalid_checks = {}

        return (invalid_checks)

    def _start(self, path_to_bin, command, reporter, redirect_std_streams):
        statsd_port = self.agentConfig.get('dogstatsd_port', "8125")
        if reporter is None:
            reporter = "statsd:%s" % str(statsd_port)

        log.info("Starting dd-tcp-rtt:")
        try:
            path_to_bin = path_to_bin or "java"

            subprocess_args = [
                path_to_bin,  # Path to the java bin
                '--check_period', str(self.check_frequency * 1000),  # between checks
                '--conf_directory', r"%s" % self.confd_path,  # Path of the conf.d directory that will be read
                '--log_level', JAVA_LOGGING_LEVEL.get(self.logging_config.get("log_level"), "INFO"),  # Log Level: Mapping from Python log level to log4j log levels
                '--log_location', r"%s" % self.logging_config.get('dd-tcp-rtt_log_file'),  # Path of the log file
                '--reporter', reporter,  # Reporter to use
                command,  # Name of the command
            ]

            if Platform.is_windows():
                #probably won't work on windows.
                return

            log.info("Running %s" % " ".join(subprocess_args))

            # Launch dd-tcp-rtt subprocess
            dd_tcp_rtt = subprocess.Popen(
                subprocess_args,
                close_fds=not redirect_std_streams,  # set to True instead of False when the streams are redirected for WIN compatibility
                stdout=subprocess.PIPE if redirect_std_streams else None,
                stderr=subprocess.PIPE if redirect_std_streams else None
            )
            self.dd_tcp_rtt = dd_tcp_rtt

            # Register SIGINT and SIGTERM signal handlers
            self.register_signal_handlers()

            if redirect_std_streams:
                # Wait for DDTcpRtt to return, and write out the stdout and stderr of DDTcpRtt to sys.stdout and sys.stderr
                out, err = dd_tcp_rtt.communicate()
                sys.stdout.write(out)
                sys.stderr.write(err)
            else:
                # Wait for DDTcpRtt to return
                dd_tcp_rtt.wait()

            return dd_tcp_rtt.returncode

        except OSError:
            bin_path_msg = "Couldn't launch dd-tcp-rtt. Is binary in your PATH?"
            log.exception(bin_path_msg)
            raise
        except Exception:
            log.exception("Couldn't launch dd-tcp-rtt")
            raise


def init(config_path=None):
    agentConfig = get_config(parse_args=False, cfg_path=config_path)
    try:
        confd_path = get_confd_path()
    except PathNotFound, e:
        log.error("No conf.d folder found at '%s' or in the directory where"
                  "the Agent is currently deployed.\n" % e.args[0])

    return confd_path, agentConfig


def main(config_path=None):
    """ DD-TCP-RTT main entry point """
    confd_path, agentConfig = init(config_path)

    tcprtt = DDTcpRtt(confd_path, agentConfig)
    return tcprtt.run()

if __name__ == '__main__':
    sys.exit(main())
