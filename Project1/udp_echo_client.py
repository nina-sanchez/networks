import threading
import time
import datetime
import json
import socket
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
    

def udp_echo_client(ip_address: str, port: int, message: str):
    # create the socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # sending data to server
    client_socket.sendto(message.encode(), (ip_address, port))

    # Receive the echoed data from the server
    echoed_data, server_address = client_socket.recvfrom(1024)

    # print the echoed data
    timestamped_print("[ECHO] ", echoed_data.decode())
    

if __name__ == "__main__":
    config_data = load_config()

    # get list from config file
    servers = config_data.get('servers', [])
    
    for server_config in servers:
        server_name = server_config.get('name', 'Unnamed Server')
        service = server_config.get('service', 'Unnamed Service')
        port = server_config.get('port', 80)
        interval = server_config.get('interval', 5)
        
    if service == "ECHO":
        # msg to server
        message = "Hello! from UDP server...."
        # call UDP echo client function
        udp_echo_client(server_name, port, message)
    else:
        pass


