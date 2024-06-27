import socket

def main():

    local_ip = '0.0.0.0'
    local_port = 8000
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    udp_socket.bind((local_ip, local_port))
    
    print("UDP Receiver is up and listening")
    
    while True:
        data, addr = udp_socket.recvfrom(1024)
        print(f"Received message from {addr}: {data.decode()}")

if __name__ == "__main__":
    main()
