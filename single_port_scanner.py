# single_port_scan.py

import socket

s = socket

def dns_check(domain):
    """
    DNS resolution check is done i.e. the domain name given by the user is converted into ipv4 address.
    If successfully resolved returns the ipv4 address.
    If resolution failed, it raises a socket.gaierror i.e, invalid domain or no DNS record which is caught and returns None value.
    """

    try:

        IP = s.gethostbyname(domain)  # Successful DNS Resolution returns the IPv4 address.
        print(f'Domain IP is: {IP}')
        return IP

    except s.gaierror:  # When domain name cannot be resolved an error is thrown and None value is returned.
        return None

def port_check(p):
    """
    This function checks whether the port given by the user falls in between valid TCP/UDP port range (0-65535).
    If true returns the port number.
    If false, then prints an error message indicating the port is out of range.
    """

    if p <0 or p > 65535:  # Port range check if out of range, notifies user.
        print(f'Port {p} is out of range.')
    else:
        return p  # If port check is valid returns the port.

def single_port_scanner(IP, port):
    """
    This function attempts to connect to the IP and port using TCP connection.
    If the port is Open, success message is print.
    If not it catches the error and notifies the user.
    The socket has a timeout of 5 seconds (set by settimeout(5)).
    This means the socket will wait up to 5 seconds for a response before raising a timeout error.
    """

    # Establishing a connection, (#IPv4 add, TCP connection)
    c = s.socket(s.AF_INET, s.SOCK_STREAM)
    c.settimeout(5)  # Timeout set to 5 seconds

    try:
        c.connect((IP, port))   # if port is open it returns None.
        print(f'Port {port} is Open')
    except s.timeout:   # when the connection takes too long and exceeds the specified timeout.
        print(f'Connection to port {port} timed out.')
    except (s.error or OSError) as a:    # Both errors are same, to catch both the errors, tuples is used here.
        print(f'Connection to port {port} failed. Error: {a}')
    finally:
        c.close()  # closes the socket connection after the scan.

if __name__ == '__main__':

    domain_to_IP = dns_check(input('Enter domain: '))
    print("Running")
    # The port scan is done after both the dns check and port check are successful.
    if domain_to_IP:  # If DNS resolution is successful proceeds to port check.
        user_port = port_check(int(input('Enter port: ')))

        if user_port is not None:  # if port check is successful proceeds to port scan.
            single_port_scanner(domain_to_IP, user_port)
    else:
        print('Domain failed to resolve.')
