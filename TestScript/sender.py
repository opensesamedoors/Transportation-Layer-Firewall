import socket

def main():
    dest_ip = '127.0.0.1'
    dest_port = 8080
    
    # UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    message = "Hello!"
    
    udp_socket.sendto(message.encode(), (dest_ip, dest_port))
    print("message sent")
    
    udp_socket.close()

if __name__ == "__main__":
    main()
