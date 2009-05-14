/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

// #define SHOW_MUTEX

#include "transport/transportapi.h"

#include <boost/scoped_array.hpp>

#include <exception>

#include "base/routingtable.h"
#include "base/utils.h"


namespace transport {
void RecvData(Transport *tsport) {
  tsport->ReceiveMessage();
#ifdef VERBOSE_DEBUG
  printf("In receive_routine(%i) - thread stopping\n",
         tsport->listening_port());
#endif
  return;
}

void ListeningLoop(UDTSOCKET listening_socket, Transport *tsport) {
#ifdef VERBOSE_DEBUG
  printf("Entered ListeningLoop(%i) socket %i\n",
         tsport->listening_port(),
         listening_socket);
#endif
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  UDTSOCKET recver;
  while (true) {
    {
      boost::mutex::scoped_lock guard(*tsport->mutex0());
      if (tsport->is_stopped()) {
#ifdef VERBOSE_DEBUG
        printf("In ListeningLoop(%i), transport has stopped.\n",
               tsport->listening_port());
        printf("ListeningLoop(%i) stopping.\n", tsport->listening_port());
#endif
        return;
      }
    }
    if (UDT::INVALID_SOCK == (recver = UDT::accept(listening_socket,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen))) {
      if (UDT::getlasterror().getErrorCode() == CUDTException::EASYNCRCV) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(10));
        continue;
      } else {
#ifdef VERBOSE_DEBUG
        printf("ListeningLoop(%i) stopping.\n", tsport->listening_port());
#endif
        return;
      }
    }
    // UDT Options
    bool blocking = false;
    UDT::setsockopt(recver, 0, UDT_RCVSYN, &blocking, sizeof(blocking));
    char clienthost[NI_MAXHOST];
    char clientservice[NI_MAXSERV];
    getnameinfo(reinterpret_cast<sockaddr *>(&clientaddr),
                addrlen,
                clienthost,
                sizeof(clienthost),
                clientservice,
                sizeof(clientservice),
                NI_NUMERICHOST|NI_NUMERICSERV);
    sockaddr peer_addr;
    int peer_addr_size = sizeof(struct sockaddr);
    if (UDT::ERROR != UDT::getpeername(recver, &peer_addr, &peer_addr_size)) {
      std::string peer_ip(inet_ntoa(((
          struct sockaddr_in *)&peer_addr)->sin_addr));
//      boost::uint16_t peer_port =
//          ntohs(((struct sockaddr_in *)&peer_addr)->sin_port);
      tsport->AddIncomingConnection(recver);
    }
  }
#ifdef VERBOSE_DEBUG
  printf("ListeningLoop(%i) stopping.\n", tsport->listening_port());
#endif
}

Transport::Transport() : stop_(true),
                         message_notifier_(0),
                         rendezvous_notifier_(0),
                         listening_loop_(),
                         recv_routine_(),
                         send_routine_(),
                         ping_rendezvous_loop_(),
                         listening_socket_(),
                         peer_address_(),
                         listening_port_(0),
                         my_rendezvous_port_(0),
                         my_rendezvous_ip_(""),
                         incoming_sockets_(),
                         outgoing_queue_(),
                         mutex_(),
                         addrinfo_hints_(),
                         addrinfo_res_(0),
                         current_id_(0),
                         cond_(),
                         ping_rendezvous_(false),
                         directly_connected_(false) {
  for (int i = 0; i < 20; ++i) {
    boost::shared_ptr<boost::mutex> mutex(new boost::mutex);
    mutex_.push_back(mutex);
  }
  UDT::startup();
}


int Transport::Start(uint16_t port,
                     boost::function<void(const std::string&,
                                          const boost::uint32_t&)> on_message,
                     boost::function<void(const bool&,
                                          const std::string&,
                                          const boost::uint16_t&)>
                         notify_dead_server) {
  if (!stop_)
    return 1;
  listening_port_ = port;
  UDT::startup();
  // addrinfo hints;
  // addrinfo* res;
  memset(&addrinfo_hints_, 0, sizeof(struct addrinfo));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  // hints.ai_socktype = SOCK_DGRAM;
  std::string service = boost::lexical_cast<std::string>(port);
  if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
      &addrinfo_res_)) {
    return 1;  // try and start with another port then !!
  }
  listening_socket_ = UDT::socket(addrinfo_res_->ai_family,
                                  addrinfo_res_->ai_socktype,
                                  addrinfo_res_->ai_protocol);
  // UDT Options
  bool blockng = false;
  UDT::setsockopt(listening_socket_, 0, UDT_RCVSYN, &blockng, sizeof(blockng));
  if (UDT::ERROR == UDT::bind(listening_socket_, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
    return 1;
  }
  // freeaddrinfo(res);
  if (UDT::ERROR == UDT::listen(listening_socket_, 10)) {
#ifdef VERBOSE_DEBUG
    printf("In Transport::Start(%i), ", listening_port_);
    printf("failed to start listening socket %i.\n",
           listening_socket_);
#endif
    return 1;
  }
  stop_ = false;
  // start the listening loop
  try {
    listening_loop_ = boost::shared_ptr<boost::thread>
        (new boost::thread(&ListeningLoop, listening_socket_, this));
    recv_routine_ =  boost::shared_ptr<boost::thread>
        (new boost::thread(&RecvData, this));
    send_routine_ = boost::shared_ptr<boost::thread>
        (new boost::thread(&Transport::SendHandle, this));
    ping_rendezvous_loop_ = boost::shared_ptr<boost::thread>
        (new boost::thread(&Transport::PingHandle, this));
  } catch(const boost::thread_resource_error& ) {
    stop_ = true;
    int result = UDT::close(listening_socket_);
    if (result != 0) {
#ifdef VERBOSE_DEBUG
      printf("In Transport::Start(%i), ", listening_port_);
      printf("failed to close listening socket %i - UDT error %i.\n",
             listening_socket_,
             result);
#endif
    }
    return 1;
  }
  message_notifier_ = on_message;
  rendezvous_notifier_ = notify_dead_server;
  current_id_ = base::generate_next_transaction_id(current_id_);
  return 0;
}

int Transport::Send(boost::uint32_t connection_id,
           const std::string &data, DataType type) {
  std::map<boost::uint32_t, IncomingData>::iterator it;
  {
#ifdef SHOW_MUTEX
  printf("In Transport::Send(%i), outside first lock.\n", listening_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[1]);
#ifdef SHOW_MUTEX
  printf("In Transport::Send(%i), inside first lock.\n", listening_port_);
#endif
  it = incoming_sockets_.find(connection_id);
  if (it == incoming_sockets_.end()) {
    return 1;
  }
  }
  UDTSOCKET skt = (*it).second.u;
  if (type == STRING) {
    int64_t data_size = data.size();
    struct OutgoingData out_data = {skt, data_size, 0,
      boost::shared_array<char>(new char[data_size]), false};
    memcpy(out_data.data.get(),
      const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
    {
#ifdef SHOW_MUTEX
      printf("In Transport::Send(%i), outside second lock.\n", listening_port_);
#endif
      boost::mutex::scoped_lock(*mutex_[2]);
#ifdef SHOW_MUTEX
      printf("In Transport::Send(%i), inside second lock.\n", listening_port_);
#endif
      outgoing_queue_.push_back(out_data);
    }
  } else if (type == FILE) {
    char *file_name = const_cast<char*>(static_cast<const char*>(data.c_str()));
    std::fstream ifs(file_name, std::ios::in | std::ios::binary);
    ifs.seekg(0, std::ios::end);
    int64_t data_size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    // send file size information
    if (UDT::ERROR == UDT::send(skt, reinterpret_cast<char*>(&data_size),
        sizeof(int64_t), 0)) {
      return 1;
    }
    // send the file
    if (UDT::ERROR == UDT::sendfile(skt, ifs, 0, data_size)) {
      return 1;
    }
  }
  return 0;
}

int Transport::Send(const std::string &remote_ip,
           uint16_t remote_port,
           const std::string &rendezvous_ip,
           uint16_t rendezvous_port,
           const std::string &data,
           DataType type,
           boost::uint32_t *conn_id,
           bool keep_connection) {
  UDTSOCKET skt;
  int result = 0;
  // the node receiver is directly connected, no rendezvous information
  if (rendezvous_ip == "" && rendezvous_port == 0) {
    if (!Connect(&skt, remote_ip, remote_port, false)) {
#ifdef VERBOSE_DEBUG
      printf("In Transport::Send(%i), ", listening_port_);
      printf("failed to connect to remote port %i socket %i.\n",
             remote_port,
             skt);
#endif
      result = UDT::close(skt);
#ifdef VERBOSE_DEBUG
      if (result != 0) {
        printf("In Transport::Send(%i), ", listening_port_);
        printf("failed to close remote port %i socket %i - UDT error %i.\n",
               remote_port,
               skt,
               result);
      }
#endif
      return 1;
    }
    if (type == STRING) {
      int64_t data_size = data.size();
      struct OutgoingData out_data = {skt, data_size, 0,
        boost::shared_array<char>(new char[data_size]), false};
      memcpy(out_data.data.get(),
        const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
      {
        boost::mutex::scoped_lock guard(*mutex_[3]);
        outgoing_queue_.push_back(out_data);
      }
    } else if (type == FILE) {
      // open the file
      char *file_name =
        const_cast<char*>(static_cast<const char*>(data.c_str()));
      std::fstream ifs(file_name, std::ios::in | std::ios::binary);
      ifs.seekg(0, std::ios::end);
      int64_t data_size = ifs.tellg();
      ifs.seekg(0, std::ios::beg);
      // send file size information
      if (UDT::ERROR == UDT::send(skt, reinterpret_cast<char*>(&data_size),
          sizeof(int64_t), 0)) {
        return 1;
      }
      // send the file
      if (UDT::ERROR == UDT::sendfile(skt, ifs, 0, data_size)) {
        return 1;
      }
    }
    if (keep_connection)
      AddIncomingConnection(skt, conn_id);
  } else {
    UDTSOCKET rend_skt;
    if (!Connect(&rend_skt, rendezvous_ip, rendezvous_port, false)) {
#ifdef VERBOSE_DEBUG
      printf("In Transport::Send(%i), ", listening_port_);
      printf("failed to connect to rendezvouz port %i socket %i.\n",
             rendezvous_port,
             rend_skt);
#endif
      result = UDT::close(rend_skt);
#ifdef VERBOSE_DEBUG
      if (result != 0) {
        printf("In Transport::Send(%i), ", listening_port_);
        printf("failed to close rendezvouz port %i socket %i - UDT error %i.\n",
               rendezvous_port,
               rend_skt,
               result);
      }
#endif
      return 1;
    }
    HolePunchingMsg msg;
    msg.set_ip(remote_ip);
    msg.set_port(remote_port);
    msg.set_type(FORWARD_REQ);
#ifdef VERBOSE_DEBUG
    printf("In Transport::Send(%i), HolePunchingMsg is: %s\n",
           listening_port_,
           msg.DebugString().c_str());
#endif
    std::string ser_msg;
    msg.SerializeToString(&ser_msg);
    int64_t rend_data_size = ser_msg.size();

    // send file size information
    if (UDT::ERROR == UDT::send(rend_skt,
        reinterpret_cast<char*>(&rend_data_size),
        sizeof(rend_data_size), 0)) {
      UDT::close(rend_skt);
      return 1;
    }

    if (UDT::ERROR == UDT::send(rend_skt, ser_msg.c_str(), rend_data_size, 0)){
      UDT::close(rend_skt);
      return 0;
    }
    // TODO(jose): establish connect in a thread or in another asynchronous
    // way to avoid blocking in the upper layers
//    struct OutgoingData out_rend_data = {rend_skt, rend_data_size, 0,
//      boost::shared_array<char>(new char[rend_data_size]), false};
//    memcpy(out_rend_data.data.get(),
//      const_cast<char*>(static_cast<const char*>(ser_msg.c_str())),
//      rend_data_size);
//    {
//      boost::mutex::scoped_lock(out_mutex_);
//      outgoing_queue_.push_back(out_rend_data);
//    }
//    printf("time: %s\n", make_daytime_string().c_str());
//    boost::this_thread::sleep(boost::posix_time::seconds(2));
//    printf("time: %s\n", make_daytime_string().c_str());
    int retries = 4;
    bool connected = false;
    for (int i = 0; i < retries && !connected; i++) {
      if (Connect(&skt, remote_ip, remote_port, false))
        connected = true;
    }
    if (!connected) {
#ifdef VERBOSE_DEBUG
      printf("In Transport::Send(%i), ", listening_port_);
      printf("failed to connect to remote port %i socket %i.\n",
             remote_port,
             skt);
#endif
      result = UDT::close(skt);
#ifdef VERBOSE_DEBUG
      if (result != 0) {
        printf("In Transport::Send(%i), ", listening_port_);
        printf("failed to close remote socket %i - UDT error %i.\n",
               skt,
               result);
      }
#endif
      return 1;
    }

    int64_t data_size = data.size();
    struct OutgoingData out_data = {skt, data_size, 0,
      boost::shared_array<char>(new char[data_size]), false};
    memcpy(out_data.data.get(),
        const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
    {
      boost::mutex::scoped_lock guard(*mutex_[4]);
      outgoing_queue_.push_back(out_data);
    }
    if (keep_connection)
      AddIncomingConnection(skt, conn_id);
  }
  return 0;
}

void Transport::Stop() {
  {
#ifdef SHOW_MUTEX
    printf("In Transport::Stop(%i), outside lock.\n", listening_port_);
#endif
    boost::mutex::scoped_lock guard(*mutex_[5]);
#ifdef SHOW_MUTEX
    printf("In Transport::Stop(%i), inside lock.\n", listening_port_);
#endif
    if (stop_) {
#ifdef VERBOSE_DEBUG
      printf("In Transport::Stop(), stop_ is already true.\n");
#endif
      return;
    }
    stop_ = true;
  }
  if (send_routine_.get()) {
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), waiting for send_routine_ to join.\n",
           listening_port_);
#endif
    send_routine_->join();
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), send_routine_ joined.\n", listening_port_);
  } else {
    printf("In Transport::Stop(), can't get pointer to send_routine_.\n");
#endif
  }
  if (listening_loop_.get()) {
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), waiting for listening_loop_ %i to join.\n",
           listening_port_,
           listening_loop_.get());
#endif
    listening_loop_->join();
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), listning_loop_ joined.\n", listening_port_);
  } else {
    printf("In Transport::Stop(), can't get pointer to listening_loop_.\n");
#endif
  }
  if (recv_routine_.get()) {
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), waiting for recv_routine_ %i to join.\n",
           listening_port_,
           recv_routine_.get());
#endif
    recv_routine_->join();
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), recv_routine_ joined.\n", listening_port_);
  } else {
    printf("In Transport::Stop(), can't get pointer to recv_routine_.\n");
#endif
  }
  if (ping_rendezvous_loop_.get()) {
    {
#ifdef SHOW_MUTEX
      printf("In Transport::Stop(%i), outside second lock.\n", listening_port_);
#endif
      boost::mutex::scoped_lock lock(*mutex_[6]);
#ifdef SHOW_MUTEX
      printf("In Transport::Stop(%i), inside second lock.\n", listening_port_);
#endif
      if (!ping_rendezvous_) {
        ping_rendezvous_ = true;
      }
      cond_.notify_one();
    }
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), waiting for ping_rendezvs_loop_ to join.\n",
           listening_port_);
#endif
    ping_rendezvous_loop_->join();
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(%i), png_rndzvs_lp_ joined.\n", listening_port_);
  } else {
    printf("In Transport::Stop(), can't get ptr to ping_rendezvouz_loop_.\n");
#endif
  }
  int result = UDT::close(listening_socket_);
#ifdef VERBOSE_DEBUG
  printf("In Transport::Stop(), result of close(listening_socket_) is %i.\n",
         result);
#endif
  std::map<boost::uint32_t, IncomingData>::iterator it;
  for (it = incoming_sockets_.begin(); it != incoming_sockets_.end(); it++) {
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(), resetting.\n");
#endif
//    delete [] (*it).second.data;
    (*it).second.data.reset();
    result = UDT::close((*it).second.u);
#ifdef VERBOSE_DEBUG
    printf("In Transport::Stop(), result of close(%i) is %i.\n",
           (*it).second.u,
           result);
#endif
  }
  incoming_sockets_.clear();
  outgoing_queue_.clear();
  message_notifier_ = 0;
  freeaddrinfo(addrinfo_res_);
}

void Transport::ReceiveMessage() {
  timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 1000;
  UDT::UDSET readfds;
  while (true) {
#ifdef VERBOSE_DEBUG
    if (stop_)
      printf("In Transport::ReceiveMessage(%i), transport has stopped.\n",
             listening_port());
#endif
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    {
      boost::mutex::scoped_lock guard(*mutex_[7]);
      if (stop_) {
        printf("In Transport::ReceiveMessage(%i), transport has stopped.\n",
               listening_port());
        printf("recieve_routine_(%i) stopping.\n", listening_port());
        return;
      }
    }
    // read data.
    std::list<boost::uint32_t> dead_connections_ids;
    std::map<boost::uint32_t, IncomingData>::iterator it;
    {
//    printf("In Transport::ReceiveMessage(%i), outside second lock.\n",
//           listening_port_);
    boost::mutex::scoped_lock guard(*mutex_[7]);
//    printf("In Transport::ReceiveMessage(%i), inside second lock.\n",
//           listening_port_);
    UD_ZERO(&readfds);
    for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
        it++) {
      // UD_ZERO(&readfds);
      // Checking if socket is connected
      if (UDT::send((*it).second.u, NULL, 0, 0) == 0) {
        UD_SET((*it).second.u, &readfds);
      } else {
#ifdef VERBOSE_DEBUG
        printf("In Transport::ReceiveMessage(%i)", listening_port_);
        printf(" - tried to kill connection %i == socket %i.\n",
               (*it).first,
               (*it).second.u);
#endif
        dead_connections_ids.push_back((*it).first);
      }
    }
    }
    int res = UDT::select(0, &readfds, NULL, NULL, &tv);
    {
//    printf("In Transport::ReceiveMessage(%i), outside third lock.\n",
//           listening_port_);
    boost::mutex::scoped_lock guard(*mutex_[7]);
//    printf("In Transport::ReceiveMessage(%i), inside third lock.\n",
//           listening_port_);
    if (res != UDT::ERROR) {
      for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
           ++it) {
        if (UD_ISSET((*it).second.u, &readfds)) {
          int result = 0;
          // save the remote peer address
          int peer_addr_size = sizeof(struct sockaddr);
          if (UDT::ERROR == UDT::getpeername((*it).second.u, &peer_address_,
              &peer_addr_size))
            continue;
          if ((*it).second.expect_size == 0) {
            // get size information
            int64_t size;
            if (UDT::ERROR == UDT::recv((*it).second.u,
                reinterpret_cast<char*>(&size), sizeof(size), 0)) {
              if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCRCV) {
#ifdef DEBUG
                printf("error recv msg size: %s\n",
                       UDT::getlasterror().getErrorMessage());
#endif
                result = UDT::close((*it).second.u);
#ifdef VERBOSE_DEBUG
                printf("In Transport::ReceiveMessage(%i), ", listening_port_);
                printf("closed socket %i with UDT result %i.\n",
                       (*it).second.u,
                       result);
#endif
//                delete [] (*it).second.data;
                (*it).second.data.reset();
                incoming_sockets_.erase(it);
                break;
              }
              continue;
            }
            if (size > 0) {
              (*it).second.expect_size = size;
            } else {
              result = UDT::close((*it).second.u);
#ifdef VERBOSE_DEBUG
              printf("In Transport::ReceiveMessage(%i), ", listening_port_);
              printf("closed socket %i with UDT result %i.\n",
                     (*it).second.u,
                     result);
#endif
//              delete [] (*it).second.data;
              (*it).second.data.reset();
              incoming_sockets_.erase(it);
              break;
            }
          } else {
            if ((*it).second.data == NULL)
              (*it).second.data = boost::shared_array<char>
                  (new char[(*it).second.expect_size]);
//              (*it).second.data = new char[(*it).second.expect_size];
            int rsize = 0;
            if (UDT::ERROR == (rsize = UDT::recv((*it).second.u,
                (*it).second.data.get() + (*it).second.received_size,
                (*it).second.expect_size - (*it).second.received_size,
                0))) {
              if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCRCV) {
#ifdef DEBUG
                printf("error recv msg: %s\n",
                       UDT::getlasterror().getErrorMessage());
#endif
                result = UDT::close((*it).second.u);
#ifdef VERBOSE_DEBUG
                printf("In Transport::ReceiveMessage(%i), ", listening_port_);
                printf("closed socket %i with UDT result %i.\n",
                       (*it).second.u,
                       result);
#endif
//                delete [] (*it).second.data;
                (*it).second.data.reset();
                incoming_sockets_.erase(it);
                break;
              }
              continue;
            }
            (*it).second.received_size += rsize;
            if ((*it).second.expect_size <= (*it).second.received_size) {
              std::string message((*it).second.data.get(),
                                  (*it).second.expect_size);
              boost::uint32_t connection_id = (*it).first;
//              delete [] (*it).second.data;
              (*it).second.data.reset();
              (*it).second.expect_size = 0;
              (*it).second.received_size = 0;
              if (HandleRendezvousMsgs(message)) {
                result = UDT::close((*it).second.u);
#ifdef VERBOSE_DEBUG
                printf("In Transport::ReceiveMessage(%i), ", listening_port_);
                printf("closed socket %i with UDT result %i.\n",
                       (*it).second.u,
                       result);
#endif
                incoming_sockets_.erase(it);
              } else {
#ifdef VERBOSE_DEBUG
                printf("In Transport::ReceiveMessage(%i), ", listening_port_);
                printf("connection_id = %i.\n",
                       connection_id);
#endif
                message_notifier_(message, connection_id);
              }
              break;
            }
          }
        }
      }
#ifdef VERBOSE_DEBUG
    } else {
      printf("In Transport::ReceiveMessage(%i), error - ", listening_port_);
      printf("Can't get receive socket.\n");
#endif
    }
    // Deleting dead connections
    std::list<boost::uint32_t>::iterator it1;
    for (it1 = dead_connections_ids.begin(); it1 != dead_connections_ids.end();
         ++it1) {
#ifdef VERBOSE_DEBUG
      printf("In Transport::ReceiveMessage(%i)", listening_port_);
      printf(" - closing dead connection %i == socket %i.\n",
             *it1,
             incoming_sockets_[*it1].u);
#endif
      int result = UDT::close(incoming_sockets_[*it1].u);
#ifdef VERBOSE_DEBUG
      printf("In Transport::ReceiveMessage(%i), ", listening_port_);
      printf("closed socket %i with UDT result %i.\n",
             incoming_sockets_[*it1].u,
             result);
#endif
      result = incoming_sockets_.erase(*it1);
#ifdef VERBOSE_DEBUG
      if (result != 1)
        printf("Didn't remove dead connection (%i) from incoming_sockets_.\n",
               *it1);
#endif
    }
    }
  }
}

void Transport::AddIncomingConnection(UDTSOCKET u, boost::uint32_t *conn_id) {
#ifdef SHOW_MUTEX
  printf("In Transport::AddIncomingConnection(%i) first, outside lock.\n",
         listening_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[8]);
#ifdef SHOW_MUTEX
  printf("In Transport::AddIncomingConnection(%i) first, inside lock.\n",
         listening_port_);
#endif
  current_id_ = base::generate_next_transaction_id(current_id_);
  struct IncomingData data = {u, 0, 0, boost::shared_array<char>(NULL)};
  // printf("id for connection = %d\n", current_id_);
  incoming_sockets_[current_id_] = data;
  *conn_id = current_id_;
}

void Transport::AddIncomingConnection(UDTSOCKET u) {
#ifdef SHOW_MUTEX
  printf("In Transport::AddIncomingConnection(%i) second, outside lock.\n",
         listening_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[9]);
#ifdef SHOW_MUTEX
  printf("In Transport::AddIncomingConnection(%i) second, inside lock.\n",
         listening_port_);
#endif
  current_id_ = base::generate_next_transaction_id(current_id_);
  struct IncomingData data = {u, 0, 0, boost::shared_array<char>(NULL)};
  // printf("id for connection = %d\n", current_id_);
  incoming_sockets_[current_id_] = data;
}

void Transport::CloseConnection(boost::uint32_t connection_id) {
#ifdef SHOW_MUTEX
  printf("In Transport::CloseConnection(%i), outside lock.\n", listening_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[10]);
#ifdef SHOW_MUTEX
  printf("In Transport::CloseConnection(%i), inside lock.\n", listening_port_);
#endif
  std::map<boost::uint32_t, IncomingData>::iterator it;
  it = incoming_sockets_.find(connection_id);
  if (it != incoming_sockets_.end()) {
    if (incoming_sockets_[connection_id].data != NULL)
//      delete [] incoming_sockets_[connection_id].data;
      incoming_sockets_[connection_id].data.reset();
    int result = UDT::close(incoming_sockets_[connection_id].u);
#ifdef VERBOSE_DEBUG
    printf("In Transport::CloseConnection(%i), ", listening_port_);
    printf("close connection %i with UDT result %i.\n",
           connection_id,
           result);
#endif
    incoming_sockets_.erase(connection_id);
#ifdef VERBOSE_DEBUG
  } else {
    printf("In Transport::CloseConnection(%i), ", listening_port_);
    printf("connection %i is not in incoming sockets map.\n", connection_id);
#endif
  }
}

bool Transport::ConnectionExists(boost::uint32_t connection_id) {
  std::map<boost::uint32_t, IncomingData>::iterator it;
#ifdef SHOW_MUTEX
  printf("In Transport::ConnectionExists(%i), outside lock.\n",
         listening_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[11]);
#ifdef SHOW_MUTEX
  printf("In Transport::ConnectionExists(%i), inside lock.\n",
         listening_port_);
#endif
  it = incoming_sockets_.find(connection_id);
  if (it != incoming_sockets_.end()) {
    return true;
  } else {
    return false;
  }
}

void Transport::SendHandle() {
  while (true) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    {
//      printf("In Transport::SendHandle(%i), outside first lock.\n",
//             listening_port_);
      boost::mutex::scoped_lock guard(*mutex_[12]);
//      printf("In Transport::SendHandle(%i), inside first lock.\n",
//             listening_port_);
      if (stop_) return;
    }
    std::list<OutgoingData>::iterator it;
    {
//      printf("In Transport::SendHandle(%i), outside second lock.\n",
//             listening_port_);
      boost::mutex::scoped_lock guard(*mutex_[13]);
//      printf("In Transport::SendHandle(%i), inside second lock.\n",
//             listening_port_);
      for (it = outgoing_queue_.begin(); it != outgoing_queue_.end(); it++) {
        if (!it->sent_size) {
          if (UDT::ERROR == UDT::send(it->u,
              reinterpret_cast<char*>(&it->data_size), sizeof(int64_t), 0)) {
            outgoing_queue_.erase(it);
            break;
          } else {
            it->sent_size = true;
          }
        }
        if (it->data_sent < it->data_size) {
          int64_t ssize;
          if (UDT::ERROR == (ssize = UDT::send(it->u,
              it->data.get() + it->data_sent,
              it->data_size - it->data_sent,
              0))) {
            outgoing_queue_.erase(it);
            break;
          }
          it->data_sent += ssize;
        } else {
          // Finished sending data
          outgoing_queue_.erase(it);
          break;
        }
      }
    }  // lock scope end here
  }
}

bool Transport::Connect(UDTSOCKET *skt, const std::string &peer_address,
      const uint16_t &peer_port, bool short_timeout) {
  bool blocking = false;
  bool reuse_addr = true;
  UDT::setsockopt(*skt, 0, UDT_RCVSYN, &blocking, sizeof(blocking));
  UDT::setsockopt(*skt, 0, UDT_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

  *skt = UDT::socket(addrinfo_res_->ai_family, addrinfo_res_->ai_socktype,
    addrinfo_res_->ai_protocol);
  if (UDT::ERROR == UDT::bind(*skt, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
#ifdef DEBUG
    printf("Bind error: %s\n", UDT::getlasterror().getErrorMessage());
#endif
    return false;
  }

  sockaddr_in peer_addr;
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(peer_port);
#ifndef WIN32
  if (inet_pton(AF_INET, peer_address.c_str(), &peer_addr.sin_addr) <= 0) {
#else
  if (INADDR_NONE == (peer_addr.sin_addr.s_addr =
    inet_addr(peer_address.c_str()))) {
#endif
#ifdef DEBUG
    printf("remote ip %s", peer_address.c_str());
    printf("bad address\n");
#endif
    return false;
  }
#ifdef DEBUG
  printf("remote address %s:%d\n", peer_address.c_str(), peer_port);
#endif
  if (UDT::ERROR == UDT::connect(*skt, reinterpret_cast<sockaddr*>(&peer_addr),
      sizeof(peer_addr))) {
#ifdef DEBUG
    printf("UDT connect error %d: %s\n", UDT::getlasterror().getErrorCode(),
        UDT::getlasterror().getErrorMessage());
#endif
    return false;
  }
  return true;
}

bool Transport::HandleRendezvousMsgs(const std::string &message) {
  HolePunchingMsg msg;
  if (!msg.ParseFromString(message))
    return false;
  if (msg.type() == FORWARD_REQ) {
    HolePunchingMsg forward_msg;
    std::string peer_ip(inet_ntoa(((\
      struct sockaddr_in *)&peer_address_)->sin_addr));
    boost::uint16_t peer_port =
      ntohs(((struct sockaddr_in *)&peer_address_)->sin_port);
    forward_msg.set_ip(peer_ip);
    forward_msg.set_port(peer_port);
    forward_msg.set_type(FORWARD_MSG);
    std::string ser_msg;
    forward_msg.SerializeToString(&ser_msg);
    boost::uint32_t conn_id;
#ifdef DEBUG
    printf("Sending HP_FORW_REQ\n");
#endif
    Send(msg.ip(), msg.port(), "", 0, ser_msg, STRING, &conn_id, false);
  } else if (msg.type() == FORWARD_MSG) {
    printf("received HP_FORW_MSG\n");
    printf("trying to connect to %s:%d\n", msg.ip().c_str(), msg.port());
    UDTSOCKET skt;
    if (Connect(&skt, msg.ip(), msg.port(), true)) {
      printf("connection OK\n");
      // AddIncomingConnection(skt);
      UDT::close(skt);
    }
  } else {
    return false;
  }
  return true;
}

void Transport::StartPingRendezvous(const bool &directly_connected,
                           std::string my_rendezvous_ip,
                           boost::uint16_t my_rendezvous_port) {
  my_rendezvous_port_ = my_rendezvous_port;
  my_rendezvous_ip_ = my_rendezvous_ip;
  {
    boost::mutex::scoped_lock lock(*mutex_[14]);
    directly_connected_ = directly_connected;
    ping_rendezvous_ = true;
    cond_.notify_one();
  }
}

void Transport::PingHandle() {
  while (true) {
    {
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), outside first lock.\n",
             listening_port_);
#endif
      boost::mutex::scoped_lock lock(*mutex_[15]);
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), inside first lock.\n",
             listening_port_);
#endif
      while (!ping_rendezvous_) {
#ifdef SHOW_MUTEX
        printf("In Transport::PingHandle, before wait.\n");
#endif
        cond_.wait(lock);
#ifdef SHOW_MUTEX
        printf("In Transport::PingHandle, after wait.\n");
#endif
      }
    }
    {
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), outside second lock.\n",
             listening_port_);
#endif
      boost::mutex::scoped_lock guard(*mutex_[16]);
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), inside second lock.\n",
             listening_port_);
#endif
      if (stop_) return;
    }
    {
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), outside third lock.\n",
             listening_port_);
#endif
      boost::mutex::scoped_lock lock(*mutex_[17]);
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), inside third lock.\n",
             listening_port_);
#endif
      if (directly_connected_) return;
    }
    UDTSOCKET skt;
    if (Connect(&skt, my_rendezvous_ip_, my_rendezvous_port_, false)) {
      UDT::close(skt);
      bool dead_rendezvous_server = false;
      // it is not dead, no nead to return the ip and port
      rendezvous_notifier_(dead_rendezvous_server, "", 0);
      boost::this_thread::sleep(boost::posix_time::seconds(8));
    } else {
      {
        boost::mutex::scoped_lock lock(*mutex_[18]);
        ping_rendezvous_ = false;
      }
      // check in case Stop was called before timeout of connection, then
      // there is no need to call rendezvous_notifier_
      {
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), outside fourth lock.\n",
             listening_port_);
#endif
      boost::mutex::scoped_lock guard(*mutex_[19]);
#ifdef SHOW_MUTEX
      printf("In Transport::PingHandle(%i), inside fourth lock.\n",
             listening_port_);
#endif
      if (stop_) return;
      }
      bool dead_rendezvous_server = true;
      rendezvous_notifier_(dead_rendezvous_server, my_rendezvous_ip_,
        my_rendezvous_port_);
    }
  }
}
bool Transport::CanConnect(const std::string &ip, const uint16_t &port) {
  UDTSOCKET skt;
  bool result = false;
  if (Connect(&skt, ip, port, false))
    result = true;
  UDT::close(skt);
  return result;
}
};  // namespace transport
