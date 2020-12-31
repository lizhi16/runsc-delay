import socket
import subprocess

socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get ip
hostname = socket.gethostname()
host = socket.gethostbyname(hostname)

port = 8080
socketserver.bind((host, port))
socketserver.listen(5)

while True:
    clientsocket,addr = socketserver.accept()
    recvmsg = clientsocket.recv(1024)
    strData = recvmsg.decode("utf-8")
    if strData != "":
        cmd = "syscall " + strData
        p = subprocess.Popen(cmd, shell=True)
        print(strData)

socketserver.close()
