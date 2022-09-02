from socket import socket, AF_INET, SOCK_STREAM
import sys

HOST = "127.0.0.1"
PORT = 9000

def main(query_file):
  print("Hello World!")
  s = socket(AF_INET, SOCK_STREAM)
  s.connect((HOST,PORT))

  with open(query_file) as fp:
      q = fp.readline()
      while q:
          s.sendall(q.encode("utf-8"))
          reply = s.recv(1024)
          print(reply)
          q = fp.readline()

  s.close()

if __name__== "__main__":
  main(sys.argv[1])
