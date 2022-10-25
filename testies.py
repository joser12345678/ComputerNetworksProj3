import socket



if __name__ == '__main__':
    query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query_sock.settimeout(1)
    query_sock.sendto(b'echo', ('8.8.8.8', 53))
    msgFromServer, addr = query_sock.recvfrom(4096)
    print(type(msgFromServer))
