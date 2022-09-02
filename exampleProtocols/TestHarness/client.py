from socket import socket, AF_INET, SOCK_STREAM
import sys

HOST = "127.0.0.1"
PORT = 9000

def main(sessionid):
  print("Hello World!")
  s = socket(AF_INET, SOCK_STREAM)
  s.connect((HOST,PORT))

  reset = "RESET:/tmp/example_protocol/protocolBasic"+sessionid+".log"

  s.sendall(reset.encode("utf-8"))
  reply = s.recv(1024)
  print(reply)

  s.sendall("INIT".encode("utf-8"))
  reply = s.recv(1024)
  print(reply)

  s.sendall("AUTH".encode("utf-8"))
  reply = s.recv(1024)
  print(reply)

  s.sendall("DATA".encode("utf-8"))
  reply = s.recv(1024)
  print(reply)

  s.sendall("CLOSE".encode("utf-8"))
  print(reply)

  s.close()

if __name__== "__main__":
  main(sys.argv[1])
