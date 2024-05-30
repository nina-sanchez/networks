import threading
import time
import datetime
import json
import socket
import signal
from typing import Any, Dict

shutdown_flag: bool = False

# from course provided code
def timestamped_print(message_type: str, status: str, data: str, *args, **kwargs):
    """
    Custom print function that adds a timestamp to the beginning of the message.

    Args:
        message_type (str): The type of message (e.g., ping, ICMP, DNS).
        status (str): The status of the message (e.g., True, False).
        data (str): The data associated with the message.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments. These are passed to the built-in print function.
    """
    # Get the current time and format it
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print the timestamp followed by the formatted message
    print(f"[{timestamp}]  [{message_type}] [{status}] [{data}]", *args, **kwargs)

# from course provided code
def signal_handler(signum: int, frame: any):
    global shutdown_flag 
    shutdown_flag = True
    timestamped_print("signal", "True", "Shutdown signal received. Initiating graceful shutdown....")

# from course provided code
def create_message(action: str, data: Any = None, count: int = 0) -> str:
    message: Dict[str, Any] = {"type": action, "data": data, "count": count}
    return json.dumps(message)

# from course provided code
def parse_message(message: str) -> Dict[str, Any]:
    return json.loads(message)

# from course provided code
def execute_services(server_info: Dict[str, Any], sock: socket.socket) -> None:
    while not shutdown_flag:
        for server in server_info["servers"]:
            service = server["service"]
            interval = server["interval"]
            if service == "ping" or service == "TCP" or service == "traceroute" or service == "HTTPS" or service == "UDP" or service == "DNS" or service == "NTP" or service == "HTTP":
                message = create_message("execute", data=server, count=interval)
                sock.send(message.encode('utf-8'))
                timestamped_print("client", "True", f"sending information to server.. [{service}]")
                time.sleep(interval)

# handles the server messages that are recieved once the information is fetched
def handle_server_message(sock: socket.socket) -> None:
    global shutdown_flag
    try:
        # while can loop
        while not shutdown_flag:
            try:
                # sending the mesaage
                message_bytes: bytes = sock.recv(1024)
                # if error
                if not message_bytes:
                    timestamped_print("client", "False", "Server connection closed.")
                    break
                # creates what the message is
                message: str = message_bytes.decode('utf-8')
                # stating what the parsed message is
                parsed_message: Dict[str, Any] = parse_message(message)
                # stating what we are looking for
                message_type = parsed_message["type"]
                # setting data
                data = parsed_message.get("data", [])
                # if returned ping results
                if message_type == "ping_result":
                    formatted_data = f"{data[0]} - {data[1]} ms"
                    timestamped_print("ping", "True", formatted_data)
                # if returned icmp results
                elif message_type == "icmp_result":
                    formatted_data = f"{data[0]} - {data[1]} ms"
                    timestamped_print("ICMP", "True", formatted_data)
                # if returned dns results
                elif message_type == "dns_result":
                    formatted_data = f"Records Results: {data}"
                    timestamped_print("DNS", "True", formatted_data)
                # if results are tcp
                elif message_type == "tcp_result":
                    formatted_data = f"{data}"
                    timestamped_print("TCP", "True", formatted_data)
                # if results are traceroute
                elif message_type == "traceroute_result":
                    formatted_data = f"{data}"
                    timestamped_print("traceroute", "True", formatted_data)
                # if results are https
                elif message_type == "https_result":
                    formatted_data = f"{data}"
                    timestamped_print("HTTPS", "True", formatted_data)
                # if results are http
                elif message_type == "http_result":
                    formatted_data = f"{data}"
                    timestamped_print("HTTP", "True", formatted_data)
                # if results are udp
                elif message_type == "udp_result":
                    timestamped_print("UDP", "True", formatted_data)
                # if results are ntp
                elif message_type == "ntp_result":
                    timestamped_print("NTP", "True", formatted_data)
                else:
                    timestamped_print("UDP", "False", str(parsed_message))
            except socket.error:
                timestamped_print("client", "False", "Lost connection to server.... trying to reconnect")
                break
    finally:
        if not shutdown_flag:
            reconnect()

# from course content
def reconnect():
    global shutdown_flag
    while not shutdown_flag:
        try:
            timestamped_print("client", "True", "Attempting to reconnect to the server...")
            start_client()
            break
        except socket.error:
            timestamped_print("client", "False", "Reconnection failed. Trying again in 5 seconds...")
            time.sleep(5)

def start_client():
    global shutdown_flag
    host: str = 'localhost'
    port: int = 54321
    client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((host, port))
        timestamped_print("client", "True", "Connected to server")
        
        # read server information from config.json
        with open("config.json", "r") as file:
            server_info = json.load(file)
        
        # start thread for executing services
        service_thread = threading.Thread(target=execute_services, args=(server_info, client_socket), daemon=True)
        service_thread.start()
        
        # start thread for handling server messages
        server_message_thread = threading.Thread(target=handle_server_message, args=(client_socket,), daemon=True)
        server_message_thread.start()
        
        # wait for threads to finish
        service_thread.join()
        server_message_thread.join()
        
    except socket.error as e:
        print(f"[Client] Socket connection error: {e}, trying to reconnect...")
    
    finally:
        client_socket.close()
        timestamped_print("client", "True", "Client shutdown gracefully")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    start_client()
