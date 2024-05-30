# downloads
# pip install requests
# pip install dnspython
# pip install ntplib
# pip install prompt_toolkit

import threading
import time
import datetime
import json
import socket
import struct
import zlib
import random
import string
import os
import requests
import signal
import dns.resolver
import dns.exception
import ntplib
import subprocess
from time import ctime
from typing import Any, Dict
from socket import gaierror
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from typing import Tuple, Optional, Any
from queue import Queue
from collections import defaultdict

shutdown_flag: bool = False

client_id_map: Dict[int, str] = {}
next_client_id: int = 1
client_sockets: Dict[str, socket.socket] = {}
client_queues: Dict[str, Queue] = defaultdict(Queue)


# code taken from course content
def signal_handler(signum: int, frame: Any) -> None:
    global shutdown_flag
    shutdown_flag = True
    print("\nShutdown signal recieved... graceful shutdown")
    
# code taken from course content
def generate_random_string(length: int) -> str:
    return ''.json(random.choice(string.ascii_letters) for _ in range(length))

# code taken from course content
def create_message(action: str, data: Any = None, count: int = 0) -> str:
    message: Dict[str, Any] = {"type": action, "data": data, "count": count}
    return json.dumps(message)

# code taken from course content
def create_to_send(action: Any = None):
    message = action
    return json.dumps(message)

# code taken from course content
def parse_message(message: str) -> Dict[str, Any]:
    return json.loads(message)

# code taken from course content
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

# code taken from course content
def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet.

    The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.

    Args:
    data (bytes): The data for which the checksum is to be calculated.

    Returns:
    int: The calculated checksum.
    """

    s: int = 0  # Initialize the sum to 0.

    # Iterate over the data in 16-bit (2-byte) chunks.
    for i in range(0, len(data), 2):
        # Combine two adjacent bytes (8-bits each) into one 16-bit word.
        # data[i] is the high byte, shifted left by 8 bits.
        # data[i + 1] is the low byte, added to the high byte.
        # This forms one 16-bit word for each pair of bytes.
        w: int = (data[i] << 8) + (data[i + 1])
        s += w  # Add the 16-bit word to the sum.

    # Add the overflow back into the sum.
    # If the sum is larger than 16 bits, the overflow will be in the higher bits.
    # (s >> 16) extracts the overflow by shifting right by 16 bits.
    # (s & 0xffff) keeps only the lower 16 bits of the sum.
    # The two parts are then added together.
    s = (s >> 16) + (s & 0xffff)

    # Complement the result.
    # ~s performs a bitwise complement (inverting all the bits).
    # & 0xffff ensures the result is a 16-bit value by masking the higher bits.
    s = ~s & 0xffff
    
    return s  # Return the calculated checksum.

# code taken from course content
def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, sequence_number: int = 1, data_size: int = 192) -> bytes:
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    Args:
    icmp_type (int): The type of the ICMP packet. Default is 8 (Echo Request).
    icmp_code (int): The code of the ICMP packet. Default is 0.
    sequence_number (int): The sequence number of the ICMP packet. Default is 1.
    data_size (int): The size of the data payload in the ICMP packet. Default is 192 bytes.

    Returns:
    bytes: A bytes object representing the complete ICMP packet.

    Description:
    The function generates a unique ICMP packet by combining the specified ICMP type, code, and sequence number
    with a data payload of a specified size. It calculates a checksum for the packet and ensures that the packet
    is in the correct format for network transmission.
    """

    # Get the current thread identifier and process identifier.
    # These are used to create a unique ICMP identifier.
    thread_id = threading.get_ident()
    process_id = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    # The & 0xffff ensures the result is within the range of an unsigned 16-bit integer (0-65535).
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Pack the ICMP header fields into a bytes object.
    # 'bbHHh' is the format string for struct.pack, which means:
    # b - signed char (1 byte) for ICMP type
    # b - signed char (1 byte) for ICMP code
    # H - unsigned short (2 bytes) for checksum, initially set to 0
    # H - unsigned short (2 bytes) for ICMP identifier
    # h - short (2 bytes) for sequence number
    header: bytes = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create the data payload for the ICMP packet.
    # It's a sequence of a single randomly chosen alphanumeric character (uppercase or lowercase),
    # repeated to match the total length specified by data_size.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    chksum: int = calculate_icmp_checksum(header + data)

    # Repack the header with the correct checksum.
    # socket.htons ensures the checksum is in network byte order.
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(chksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data

# code taken from course content
def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1) -> Tuple[Any, float] | Tuple[Any, None]:
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    This function creates a raw socket to send an ICMP Echo Request packet to the given host.
    It then waits for an Echo Reply, measuring the time taken for the round trip. If the
    specified timeout is exceeded before receiving a reply, the function returns None for the ping time.

    Args:
    host (str): The IP address or hostname of the target host.
    ttl (int): Time-To-Live for the ICMP packet. Determines how many hops (routers) the packet can pass through.
    timeout (int): The time in seconds that the function will wait for a reply before giving up.
    sequence_number (int): The sequence number for the ICMP packet. Useful for matching requests with replies.

    Returns:
    Tuple[Any, float] | Tuple[Any, None]: A tuple containing the address of the replier and the total ping time in milliseconds.
    If the request times out, the function returns None for the ping time. The address part of the tuple is also None if no reply is received.
    """

    # Create a raw socket with the Internet Protocol (IPv4) and ICMP.
    # socket.AF_INET specifies the IPv4 address family.
    # socket.SOCK_RAW allows sending raw packets (including ICMP).
    # socket.IPPROTO_ICMP specifies the ICMP protocol.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blocking operations (e.g., recvfrom).
        sock.settimeout(timeout)

        # Create an ICMP Echo Request packet.
        # icmp_type=8 and icmp_code=0 are standard for Echo Request.
        # sequence_number is used to match Echo Requests with Replies.
        packet: bytes = create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        # Send the ICMP packet to the target host.
        # The second argument of sendto is a tuple (host, port).
        # For raw sockets, the port number is irrelevant, hence set to 1.
        sock.sendto(packet, (host, 1))

        # Record the current time to measure the round-trip time later.
        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            # This will be the ICMP Echo Reply if the target host is reachable.
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time = (end - start) * 1000

            # Return the address of the replier and the total ping time.
            return addr, total_ping_time
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None

# code taken from course content
def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False) -> str:
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    Args:
    host (str): The IP address or hostname of the target host.
    max_hops (int): Maximum number of hops to try before stopping.
    pings_per_hop (int): Number of pings to perform at each hop.
    verbose (bool): If True, print additional details during execution.

    Returns:
    str: The results of the traceroute, including statistics for each hop.
    """
    # Header row for the results. Each column is formatted for alignment and width.
    results = [f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8}   {'Avg (ms)':>8}   {'Max (ms)':>8}   {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops.
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for the current TTL.
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL.
        for _ in range(pings_per_hop):
            # Ping the host with the current TTL and sequence number.
            # The sequence number is incremented with TTL for each ping.
            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            # If a response is received (not None), append it to ping_times.
            if response is not None:
                ping_times.append(response)

        # If there are valid ping responses, calculate and format the statistics.
        if ping_times:
            min_time = min(ping_times)  # Minimum ping time.
            avg_time = sum(ping_times) / len(ping_times)  # Average ping time.
            max_time = max(ping_times)  # Maximum ping time.
            count = len(ping_times)  # Count of successful pings.

            # Append the formatted results for this TTL to the results list.
            results.append(f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.2f}ms {avg_time:>8.2f}ms {max_time:>8.2f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(f"{ttl:>3} {'*':<15} {'*':>8}   {'*':>8}   {'*':>8}   {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute.
        if addr and addr[0] == host:
            break

    # Join all results into a single string with newline separators and return.
    return '\n'.join(results)
    # return results

# code taken from course content
def check_server_http(url: str) -> Tuple[bool, Optional[int], str]:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a description.

    :param url: URL of the server (including http://)
    :return: Tuple (True/False, status code, description)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # The HTTP status code is a number that indicates the outcome of the request.
        # Here, we consider status codes less than 400 as successful,
        # meaning the server is up and reachable.
        # Common successful status codes are 200 (OK), 301 (Moved Permanently), etc.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code, description)
        # True if the server is up, False if an exception occurs (see except block)
        return is_up, response.status_code, "Success"

    except requests.RequestException as e:
        # This block catches any exception that might occur during the request.
        # This includes network problems, invalid URL, etc.
        # If an exception occurs, we assume the server is down.
        # Returning False for the status, None for the status code,
        # and the exception description as the description.
        return False, None, str(e)
    
def reconnect():
    # reconnecting
    pass

# code taken from course content
def check_server_https(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL with HTTPS.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a descriptive message.

    :param url: URL of the server (including https://)
    :param timeout: Timeout for the request in seconds. Default is 5 seconds.
    :return: Tuple (True/False for server status, status code, description)
    """
    try:
        # Setting custom headers for the request. Here, 'User-Agent' is set to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        # The timeout ensures that the request does not hang indefinitely.
        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        # Checking if the status code is less than 400. Status codes in the 200-399 range generally indicate success.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    except requests.ConnectionError:
        # This exception is raised for network-related errors, like DNS failure or refused connection.
        return False, None, "Connection error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # A catch-all exception for any error not covered by the specific exceptions above.
        # 'e' contains the details of the exception.
        return False, None, f"Error during request: {e}"

# code taken from course content
def check_dns_server_status(server, query, record_type) -> (bool, str):
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    try:
        # Set the DNS resolver to use the specified server
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)

# code taken from course content
def check_tcp_port(ip_address: str, port: int) -> (bool, str):
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            return True, f"Port {port} on {ip_address} is open."

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
        return False, f"Port {port} on {ip_address} timed out."

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        return False, f"Port {port} on {ip_address} is closed or not reachable."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"
    
# code taken from course content
def check_udp_port(ip_address: str, port: int, timeout: int = 3) -> (bool, str):
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. Default is 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                s.recvfrom(1024)
                return False, f"Port {port} on {ip_address} is closed."

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                return True, f"Port {port} on {ip_address} is open or no response received."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"
    
# code taken from course content   
def check_ntp_server(server: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None
    
# this function executes the different checks --> extra function
def execute_check(data: Dict[str, Any]) -> str:
    try:
        name = data["name"]
        host = data["host"]
        port = data["port"]
        service = data["service"]
        interval = data["interval"]
        server_number = data["server_number"]
        count = data.get("count", 0)
        
        # if (service != "DNS" and service != "NTP" and service != "UDP" and service != "ECHO") and not server_name.endswith(".com"):
        #     name += ".com"
            
        # service specific checks here
        # ping check
        if service == "ping":
            ping_result = ping(host)
            if ping_result is not None:
                addr, ping_time = ping_result
                return f"ping, Status: [True] [{addr[0]} - {ping_time:.2f} ms]" if (addr and ping_time is not None) else f"[{name}] (ping): Request timed out or no reply received]"
            else:
                return f"[{name}] (ping): Request timed out or no reply received"
        # tcp check
        elif service == "TCP":
            try:
                tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_socket.settimeout(5)
                tcp_socket.connect((host, port))
                return "TCP, Status: Connected successfully"
            except socket.error as e:
                return f"TCP, Status: {str(e)}"
            finally:
                tcp_socket.close()
        else:
            return f"Unknown service: {service}"
    except Exception as e:
        return f"An error occurred: {e}"


def handle_client_connection(client_socket: socket.socket, addr: str) -> None:
    global shutdown_flag
    try:
        while not shutdown_flag:
            message_bytes = client_socket.recv(1024)
            if not message_bytes:
                # empty message received --> continue listening
                continue
            message = message_bytes.decode('utf-8')
            timestamped_print("[Client] Received message from server:", message)
            try:
                parsed_message = json.loads(message)
                # process parsed_message as needed
                if parsed_message["type"] == "execute": # this is how they are read in and filtered
                    service = parsed_message["data"]["service"]
                    if service == "ping" or service == "ICMP":
                        # perform ping using the  ping function
                        host = parsed_message["data"]["host"]
                        addr, ping_time = ping(host)
                        results = ping(host)
                        if addr and ping_time is not None:
                            # response_message = create_to_send(results)
                            # response_message = create_message("ping_result", data=f"Address: {addr}, Ping Time: {ping_time} ms")
                            response_message = create_message("ping_result", data=results)
                        else:
                            response_message = create_message("ping_result", data="Ping request timed out.")
                        client_socket.send(response_message.encode('utf-8'))
                    # getting the TCP results    
                    elif service == "TCP":
                        # performing the TCP action
                        try:
                            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            tcp_socket.settimeout(5)
                            tcp_socket.connect((parsed_message["data"]["host"], parsed_message["data"]["port"]))
                            response_message = create_message("tcp_result", data="Connected successfully")
                        except socket.error as e:
                            response_message = create_message("tcp_result", data=str(e))
                        finally:
                            tcp_socket.close()
                        client_socket.send(response_message.encode('utf-8'))
                    # doing the traceroute
                    elif service == "traceroute":
                        print("traceroute")
                        traceroute_ans = traceroute(host)
                        response_message = create_message("traceroute_result", data=traceroute_ans)
                        client_socket.send(response_message.encode('utf-8'))
                    # doing the http checks
                    elif service == "HTTP":
                        # checking if the HTTP server is up
                        is_up, status_code, description = check_server_http(f"http://{host}")
                        # create a message based on the result
                        response_message = create_message("http_result", data={"is_up": is_up, "status_code": status_code, "description": description})
                        client_socket.send(response_message.encode('utf-8'))
                    # doing the https check                   
                    elif service == "HTTPS":
                        # check if the HTTPS server is up
                        is_up, status_code, description = check_server_https(f"https://{host}")
                        # create a message based on the result
                        response_message = create_message("https_result", data={"is_up": is_up, "status_code": status_code, "description": description})
                        client_socket.send(response_message.encode('utf-8'))
                    # doing the udp check             
                    elif service == "UDP":
                        try:
                            # extract the port from the message data
                            port = parsed_message["data"]["port"]
                            # checking if the UDP port is open
                            is_open, description = check_udp_port(host, port)
                            # creating a message
                            response_message = create_message("udp_result", data={"is_open": is_open, "description": description})
                            client_socket.send(response_message.encode('utf-8'))
                        except KeyError:
                            # error handling if port info is missing
                            response_message = create_message("error", data="Port information is missing")
                            client_socket.send(response_message.encode('utf-8'))                               
                    elif service == "DNS":
                        # checking DNS server 
                        status, results = check_dns_server_status(host, host, 'A')
                        # creating a msg from it
                        response_message = create_message("dns_result", data={"status": status})
                        client_socket.send(response_message.encode('utf-8'))
                    # finding the ntp                 
                    elif service == "NTP":
                        # checking the ntp server
                        status, current_time = check_ntp_server(host)
                        # making the message to send to client
                        response_message = create_message("ntp_result", data={"status": status, "current_time": current_time})
                        client_socket.send(response_message.encode('utf-8'))                         
                    else:
                        print(f"[Server] Unknown service: {service}")
            except json.JSONDecodeError:
                print("[Client] Error: Unable to parse server message as JSON")
                # handling
                continue
    except socket.error as e:
        print(f"[Client] Socket error: {e}")
        reconnect()
    except Exception as e:
        print(f"[Client] Error: {e}")
        reconnect()
        

# got code from course content
def server_commands_interface() -> None:
    global shutdown_flag
    
    commands = ["list_clients", "list_all_queues"]

    completer = WordCompleter(commands)
    
    session = PromptSession(completer=completer)
    
    while not shutdown_flag:
        with patch_stdout():
            try:
                action = session.prompt("server command: ", wrap_lines=False)
                parts = action.split()
                cmd = parts[0] if parts else ""
                if cmd == "list_clients":
                    print(f"connected clients: {len(client_id_map)}")
                    for client_id, client_identifier in client_id_map.items():
                        print(f" {client_id}: {client_identifier}")
                elif cmd == "list_all_queues":
                    print("\n All client queues: ")
                    for num_id, client_identifier in client_id_map.items():
                        queue_contents = list (client_queues[client_identifier].queue)
                        print(f"    Client ID {num_id} ({client_identifier}): {len(queue_contents)} items")
                    for item in queue_contents:
                        print(f"    {item}")
            except Exception as e:
                print(f"erorr in server command")
    
    print("server CLI closed")
    
# created using course code
def start_server() -> None:
    global shutdown_flag
    global client_id_map
    global next_client_id
    
    host: str = 'localhost'
    port: int = 54321
    server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    server_socket.settimeout(1.0)
    
    # timestamped_print(f"[Server] server listening on {host}:{port}")
    print("[Server]", "Status", f"server listening on {host}:{port}")
    
    command_thread: threading.Thread = threading.Thread(target=server_commands_interface, daemon=True)
    command_thread.start()
    
    try:
        while not shutdown_flag:
            try:
                client_socket, addr = server_socket.accept()
                print(f"[Server] accepted connection from {addr}")
                client_identifier = str(addr)
                # assign num id to the client
                client_id = next_client_id
                next_client_id += 1
                # use the clients addr as a unique identifier
                client_id_map[client_id] = client_identifier
                client_sockets[client_identifier] = client_socket
                client_queues[client_identifier] = Queue()
                client_thread: threading.Thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_identifier), daemon=True)
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Server] error in server loop: {e}")
        
        print("\n[Server] Server shutdown initiated")
    finally:
        server_socket.close()
        print("\n[Server] Server shutdown graceful")
        
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    start_server()
    
