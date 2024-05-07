import datetime
import socket
import json
from time import ctime
from socket import gaierror

def timestamped_print(*args, **kwargs):
    """
    Custom print function that adds a timestamp to the beginning of the message.

    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments. These are passed to the built-in print function.
    """
    # Get the current time and format it
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print the timestamp followed by the original message
    print(f"[{timestamp}] ", *args, **kwargs)

def load_config(filename='config.json'):
    try:
        with open(filename) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file '{filename}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"Error decoding JSON from '{filename}'.")
        return {}


def udp_echo_server(ip_address: str, port: int):
    # create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip_address, port))

    # print to terminal where it is listening
    print(f"UDP echo server is listening on {ip_address}:{port}")
    while True:
        # receive data from the client
        data, client_address = server_socket.recvfrom(1024)

        # echo the received data back to the client
        server_socket.sendto(data, client_address)

if __name__ == "__main__":
    config_data = load_config()

    # getting the servers from file
    servers = config_data.get('servers', [])
    
    for server_config in servers:
        server_name = server_config.get('name', 'Unnamed Server')
        service = server_config.get('service', 'Unnamed Service')
        port = server_config.get('port', 80)
        interval = server_config.get('interval', 5)
    
        if service == "ECHO":
            udp_echo_server(server_name, port) 
        else:
            pass

