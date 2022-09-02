from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, SHUT_RDWR
import time


HOST_client = "127.0.0.1"
PORT_client = 8124

PORT_learner = 9000

debug = 1

def main():
  while True:
    if (debug): print("Listening for learner")
    socket_listener = socket(AF_INET, SOCK_STREAM)
    socket_listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    socket_listener.bind(('127.0.0.1', PORT_learner))         
    socket_listener.listen(5)      
    (socket_learner, address) = socket_listener.accept()

    socket_to_client = socket(AF_INET, SOCK_STREAM)
    socket_to_client.connect((HOST_client,PORT_client))

    if (debug): print("Learner connected")

    closed = False

    while True:
      try :
        command_from_learner = socket_learner.recv(1024)
        query = command_from_learner.decode("utf-8").strip()
        if (debug): print("Got from learner: "+ query)
      
        if "RESET" in query:
          closed = False
          if (debug): print("RESETING")
          socket_to_client.shutdown(SHUT_RDWR)
          socket_to_client.close()
          
          socket_to_client = socket(AF_INET, SOCK_STREAM)
          socket_to_client.connect((HOST_client,PORT_client))
          socket_learner.sendall(b"\n")
        else :
          if closed:
              reply_from_client = b"ConnectionClosed\n"
              if (debug): print("      reply from client: "+ response)
              socket_learner.sendall(reply_from_client)
              continue

          socket_to_client.sendall(command_from_learner)
          reply_from_client = socket_to_client.recv(1024)
          response = reply_from_client.decode("utf-8").strip()
          
          if (debug): print("      reply from client: "+ response)
          
          if len(response) == 0:
            reply_from_client = b"ConnectionClosed\n"
            response = "ConnectionClosed"
            closed = True
            
          socket_learner.sendall(reply_from_client)
          
      except Exception as e: 
        print(e)
        if (debug): print("Socket exception, restarting\n")
        socket_to_client.close()
        break

  
if __name__== "__main__":
  main()
