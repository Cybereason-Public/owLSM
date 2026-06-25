from pytest_bdd import given, when, then, parsers
import threading
import time

from Utils.process_utils import *
from globals.system_related_globals import system_globals
from Utils.network_utils import *
from Utils.logger_utils import logger

@given(parsers.parse('I setup the fake network'))
@when(parsers.parse('I setup the fake network'))
@then(parsers.parse('I setup the fake network'))
def I_setup_the_fake_network():
    # clean network namespace and veth pair
    run_command_sync(f"ip netns del {system_globals.networking_globals.NS_NAME}")
    run_command_sync(f"ip link del {system_globals.networking_globals.VETH_HOST}")

    # setup network namespace and veth pair
    run_command_sync(f"ip netns add {system_globals.networking_globals.NS_NAME}")
    assert os.path.exists(f"/var/run/netns/{system_globals.networking_globals.NS_NAME}"), f"Network namespace '{system_globals.networking_globals.NS_NAME}' file does not exist"
    run_command_sync(f"ip link add {system_globals.networking_globals.VETH_HOST} type veth peer name {system_globals.networking_globals.VETH_NS}")
    run_command_sync(f"ip addr add {system_globals.networking_globals.SERVER_IP} dev {system_globals.networking_globals.VETH_HOST}")
    run_command_sync(f"ip -6 addr add {system_globals.networking_globals.SERVER_IPv6} dev {system_globals.networking_globals.VETH_HOST} nodad")
    run_command_sync(f"ip link set {system_globals.networking_globals.VETH_HOST} up")
    run_command_sync(f"ip link set {system_globals.networking_globals.VETH_NS} netns {system_globals.networking_globals.NS_NAME}")
    run_command_sync(f"ip netns exec {system_globals.networking_globals.NS_NAME} ip addr add {system_globals.networking_globals.CLIENT_IP} dev {system_globals.networking_globals.VETH_NS}")
    run_command_sync(f"ip netns exec {system_globals.networking_globals.NS_NAME} ip -6 addr add {system_globals.networking_globals.CLIENT_IPv6} dev {system_globals.networking_globals.VETH_NS} nodad")
    run_command_sync(f"ip netns exec {system_globals.networking_globals.NS_NAME} ip link set {system_globals.networking_globals.VETH_NS} up")
    run_command_sync(f"ip netns exec {system_globals.networking_globals.NS_NAME} ip link set lo up")
    run_command_sync(f"ip -6 addr show ")

@given(parsers.parse('I initiate a "{protocol_arg}" connection on port "{port}" and connection expected to be "{expected_connection}"'))
@when(parsers.parse('I initiate a "{protocol_arg}" connection on port "{port}" and connection expected to be "{expected_connection}"'))
@then(parsers.parse('I initiate a "{protocol_arg}" connection on port "{port}" and connection expected to be "{expected_connection}"'))
def I_initiate_a_http_connection(protocol_arg, port, expected_connection):
    protocol = PROTOCOL.from_string(protocol_arg)
    port = int(port)
    expected_connection = expected_connection.lower()
    if expected_connection == 'true':
        expected_connection = True
    elif expected_connection == 'false':
        expected_connection = False
    else:
        assert False, f"Invalid expected connection: {expected_connection}"
    
    system_globals.networking_globals.error_messages = []
    timeout = 5 
    
    server_thread = threading.Thread(
        target=lambda: get_server(protocol, port, expected_connection, timeout)
    )

    client_thread = threading.Thread(
        target=lambda: run_client(protocol, port, expected_connection, timeout)
    )
    
    server_thread.start()
    time.sleep(2)
    client_thread.start() 
    server_thread.join(timeout=timeout + 1)
    client_thread.join(timeout=timeout + 1)
    
    if system_globals.networking_globals.error_messages:
        error_log = "\n".join(system_globals.networking_globals.error_messages)
        logger.log_error(f"Scenario failed with errors:\n{error_log}")
        assert False, f"Scenario failed with errors:\n{error_log}"

def get_server(protocol, port, expected_connection, timeout):
    match protocol:
        case PROTOCOL.HTTP:  return Test_HTTP_Server(port, expected_connection, timeout)
        case PROTOCOL.HTTPS: return Test_HTTPS_Server(port, expected_connection, timeout)
        case PROTOCOL.SSH:   return Test_File_Existence_Server(timeout)
        case PROTOCOL.SFTP:  return Test_File_Existence_Server(timeout)
        case PROTOCOL.NETCAT: return Test_Netcat_Server(port, expected_connection, timeout)
        case _: assert False, f"Invalid protocol: {protocol}"

def run_client(protocol, port, expected_connection, timeout):
        fd = os.open(f"/var/run/netns/{system_globals.networking_globals.NS_NAME}", os.O_RDONLY)
        logger.log_info(f"[CLIENT] fd of namespace {system_globals.networking_globals.NS_NAME} is {fd}")
        os.setns(fd, 0)
        logger.log_info(f"[CLIENT] setns to namespace {system_globals.networking_globals.NS_NAME}")

        result = subprocess.run(['ip', 'addr', 'show', 'dev', system_globals.networking_globals.VETH_NS], capture_output=True, text=True)
        if result.returncode == 0:
            logger.log_info(f"[CLIENT] IP addresses on {system_globals.networking_globals.VETH_NS} after setns: {result.stdout.strip()}")
        else:
            logger.log_error(f"[CLIENT] Failed to get IP addresses on {system_globals.networking_globals.VETH_NS}: {result.stderr}")

        get_client(protocol, port, expected_connection, timeout).connect()
        os.close(fd)


def get_client(protocol, port, expected_connection, timeout):
    match protocol:
        case PROTOCOL.HTTP:  return Test_HTTP_Client(port, expected_connection, timeout)
        case PROTOCOL.HTTPS: return Test_HTTPS_Client(port, expected_connection, timeout)
        case PROTOCOL.SSH:   return Test_SSH_Client(port, expected_connection, timeout)
        case PROTOCOL.SFTP:  return Test_SFTP_Client(port, expected_connection, timeout)
        case PROTOCOL.NETCAT: return Test_Netcat_Client(port, expected_connection, timeout)
        case _: assert False, f"Invalid protocol: {protocol}"

        
@given(parsers.parse('I ensure the socket "{path}" exists'))
@when(parsers.parse('I ensure the socket "{path}" exists'))
@then(parsers.parse('I ensure the socket "{path}" exists'))
def I_ensure_the_socket_exists(path):
    assert create_socket(path), f"Failed to create socket: {path}"


@given('I SSH to localhost as test user')
@when('I SSH to localhost as test user')
@then('I SSH to localhost as test user')
def ssh_to_localhost_as_test_user():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('127.0.0.1', username=system_globals.USER_NAME, password=system_globals.PASSWORD, timeout=5)
    except Exception:
        pass
    finally:
        client.close()
