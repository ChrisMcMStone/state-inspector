from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from Logger import Logger


HOST_client = "127.0.0.1"
PORT_client = 8124

PORT_learner = 9000

debug = 1

def main():
  logger = None
  while True:
    if (debug): print("Listening for learner")
    socket_listener = socket(AF_INET, SOCK_STREAM)
    socket_listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    socket_listener.bind(('127.0.0.1', PORT_learner))         
    socket_listener.listen(5)      
    (socket_learner, address) = socket_listener.accept()

    if (debug): print("Learner connected")
    if (debug): print("Connecting to client")

    socket_to_client = socket(AF_INET, SOCK_STREAM)
    socket_to_client.connect((HOST_client,PORT_client))

    if (debug): print("Connected to client\n")

    while True:
      try :
        command_from_learner = socket_learner.recv(1024)
        query = command_from_learner.decode("utf-8").strip()
        if (debug): print("Got from learner: "+ query)
      
        if "RESET" in query:
          if (debug): print("RESETING")
          socket_learner.sendall(b"\n")
          socket_to_client.close()
          print("creating new logger at file: " + query[6:])
          logger = Logger(command_from_learner.strip()[6:])
          socket_to_client = socket(AF_INET, SOCK_STREAM)
          socket_to_client.connect((HOST_client,PORT_client))
        else :
          logger.new_input_msg(query)
          socket_to_client.sendall(command_from_learner)
          reply_from_client = socket_to_client.recv(1024)
          response = reply_from_client.decode("utf-8").strip()
          
          if (debug): print("      reply from client: "+ response)
          
          if len(response) == 0:
            reply_from_client = b"ConnClosed\n"
            response = "ConnClosed"
            
          logger.new_output_msg(response)
          socket_learner.sendall(reply_from_client)
          
      except: 
        if (debug): print("Socket exception, restarting\n")
        socket_to_client.close()
        break

  
if __name__== "__main__":
  main()
