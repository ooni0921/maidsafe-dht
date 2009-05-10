/*
Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 *  Created on: Mar 16, 2009
 *      Author: Team
 */
#include "transport/transportapi.h"
// external libs
#include <boost/scoped_array.hpp>
// c++ std libs
#include <exception>
// maidsafe libs
#include "base/routingtable.h"
#include "base/utils.h"

namespace transport {
void RecvData(Transport *tsport) {
  tsport->ReceiveMessage();
  return;
}

void ListeningLoop(UDTSOCKET listening_socket, Transport *tsport) {
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  UDTSOCKET recver;
  while (true) {
    {
      base::pd_scoped_lock guard(*tsport->pmutex());
      if (tsport->is_stopped()) return;
    }
    if (UDT::INVALID_SOCK == (recver = UDT::accept(listening_socket,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen))) {
       if (UDT::getlasterror().getErrorCode() == CUDTException::EASYNCRCV) {
         boost::this_thread::sleep(boost::posix_time::milliseconds(10));
         continue;
       } else {
         return;
       }
    }
    // UDT Options
    UDT::setsockopt(recver, 0, UDT_RCVSYN, new bool(false), sizeof(bool));  // NOLINT
    char clienthost[NI_MAXHOST];
    char clientservice[NI_MAXSERV];
    getnameinfo(reinterpret_cast<sockaddr *>(&clientaddr), addrlen, clienthost,
      sizeof(clienthost), clientservice, sizeof(clientservice),
      NI_NUMERICHOST|NI_NUMERICSERV);
    sockaddr peer_addr;
    int peer_addr_size = sizeof(struct sockaddr);
    if (UDT::ERROR != UDT::getpeername(recver, &peer_addr,
        &peer_addr_size)) {
      std::string peer_ip(inet_ntoa(((\
          struct sockaddr_in *)&peer_addr)->sin_addr));
          boost::uint16_t peer_port =
            ntohs(((struct sockaddr_in *)&peer_addr)->sin_port);
      tsport->AddIncomingConnection(recver);
    }
  }
}

int Transport::Start(uint16_t port,
                     boost::function<void(const std::string&,
                     const boost::uint32_t&)> on_message,
                     boost::function<void(const bool&, const std::string&,
                       const boost::uint16_t&)> notify_dead_server) {
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
  addrinfo_res_->ai_socktype, addrinfo_res_->ai_protocol);
  // UDT Options
  UDT::setsockopt(listening_socket_, 0, UDT_RCVSYN, new bool(false),  // NOLINT
    sizeof(false));
  if (UDT::ERROR == UDT::bind(listening_socket_, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
    return 1;
  }
  // freeaddrinfo(res);
  if (UDT::ERROR == UDT::listen(listening_socket_, 10)) {
    return 1;
  }
  stop_ = false;
  // start the listening loop
  try {
    listening_loop_ = boost::shared_ptr<boost::thread>(new boost::thread(
      boost::bind(&ListeningLoop, listening_socket_, this)));
    recv_routine_ =  boost::shared_ptr<boost::thread>(new boost::thread(
      boost::bind(&RecvData, this)));
    send_routine_ = boost::shared_ptr<boost::thread>(new boost::thread(
      boost::bind(&Transport::SendHandle, this)));
    ping_rendezvous_loop_ = boost::shared_ptr<boost::thread>(new boost::thread(
      boost::bind(&Transport::PingHandle, this)));
  } catch(boost::thread_resource_error& e) {  // NOLINT
    stop_ = true;
    UDT::close(listening_socket_);
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
  base::pd_scoped_lock gaurd(*pmutex_);
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
      boost::mutex::scoped_lock(out_mutex_);
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
  // the node receiver is directly connected, no randezvous information
  if (rendezvous_ip == "" && rendezvous_port == 0) {
    if (!Connect(&skt, remote_ip, remote_port)) {
      UDT::close(skt);
      return 1;
    }
    if (type == STRING) {
      int64_t data_size = data.size();
      struct OutgoingData out_data = {skt, data_size, 0,
        boost::shared_array<char>(new char[data_size]), false};
      memcpy(out_data.data.get(),
        const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
      {
        boost::mutex::scoped_lock(out_mutex_);
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
    if (keep_connection) {
      AddIncomingConnection(skt, conn_id);
    } else {
      // UDT::close(skt);
    }
  } else {
    UDTSOCKET rend_skt;
    if (!Connect(&rend_skt, rendezvous_ip, rendezvous_port)) {
      printf("failed to connect to rendezvous server\n");
      UDT::close(rend_skt);
      return 1;
    }
    HolePunchingMsg msg;
    msg.set_ip(remote_ip);
    msg.set_port(remote_port);
    msg.set_type(FORWARD_REQ);
    std::string ser_msg;
    msg.SerializeToString(&ser_msg);
    int64_t rend_data_size = ser_msg.size();
    struct OutgoingData out_rend_data = {rend_skt, rend_data_size, 0,
      boost::shared_array<char>(new char[rend_data_size]), false};
    memcpy(out_rend_data.data.get(),
      const_cast<char*>(static_cast<const char*>(ser_msg.c_str())),
      rend_data_size);
    {
      boost::mutex::scoped_lock(out_mutex_);
      outgoing_queue_.push_back(out_rend_data);
    }
    if (!Connect(&skt, remote_ip, remote_port)) {
      UDT::close(skt);
      return 1;
    }

    int64_t data_size = data.size();
    struct OutgoingData out_data = {skt, data_size, 0,
      boost::shared_array<char>(new char[data_size]), false};
    memcpy(out_data.data.get(),
      const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
    {
      boost::mutex::scoped_lock(out_mutex_);
      outgoing_queue_.push_back(out_data);
    }
    if (keep_connection) {
      AddIncomingConnection(skt, conn_id);
    }
  }
  return 0;
}

void Transport::Stop() {
  {
    base::pd_scoped_lock guard(*pmutex_);
    if (stop_)
      return;
    stop_ = true;
  }
  if (send_routine_.get()) {
    send_routine_->join();
  }
  if (listening_loop_.get()) {
    listening_loop_->join();
  }
  if (recv_routine_.get()) {
    recv_routine_->join();
  }
  if (ping_rendezvous_loop_.get()) {
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      if (!ping_rendezvous_) {
        ping_rendezvous_ = true;
      }
      cond_.notify_one();
    }
    ping_rendezvous_loop_->join();
  }
  UDT::close(listening_socket_);
  std::map<boost::uint32_t, IncomingData>::iterator it;
  for (it = incoming_sockets_.begin(); it != incoming_sockets_.end(); it++) {
    delete [] (*it).second.data;
    UDT::close((*it).second.u);
  }
  incoming_sockets_.clear();
  outgoing_queue_.clear();
  message_notifier_ = NULL;
  freeaddrinfo(addrinfo_res_);
}

void Transport::ReceiveMessage() {
  timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 1000;
  UDT::UDSET readfds;
  while (true) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    {
      base::pd_scoped_lock guard(*pmutex_);
      if (stop_) {
        return;
      }
    }
    // read data.
    std::list<boost::uint32_t> dead_connections_ids;
    std::map<boost::uint32_t, IncomingData>::iterator it;
    {
    base::pd_scoped_lock guard(*pmutex_);
    UD_ZERO(&readfds);
    for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
        it++) {
      // UD_ZERO(&readfds);
      // Checking if socket is connected
      if (UDT::send((*it).second.u, NULL, 0, 0) == 0) {
        UD_SET((*it).second.u, &readfds);
      } else {
        dead_connections_ids.push_back((*it).first);
      }
    }
    }
    int res = UDT::select(0, &readfds, NULL, NULL, &tv);
    {
    base::pd_scoped_lock gaurd(*pmutex_);
    if (res != UDT::ERROR) {
      for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
          it++) {
        if (UD_ISSET((*it).second.u, &readfds)) {
          // save the remote peer address
          int peer_addr_size = sizeof(struct sockaddr);
          if (UDT::ERROR == UDT::getpeername((*it).second.u, &peer_address_,
              &peer_addr_size))
            continue;
          if ((*it).second.expect_size == 0) {
            // get size information
            int64_t size;
            if (UDT::ERROR == UDT::recv((*it).second.u,
                reinterpret_cast<char*>(&size), sizeof(int64_t), 0)) {
              if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCRCV) {
                UDT::close((*it).second.u);
                delete [] (*it).second.data;
                incoming_sockets_.erase(it);
                break;
              }
              continue;
            }
            if (size > 0) {
              (*it).second.expect_size = size;
            } else {
              UDT::close((*it).second.u);
              delete [] (*it).second.data;
              incoming_sockets_.erase(it);
              break;
            }
          } else {
            if ((*it).second.data == NULL)
              (*it).second.data = new char[(*it).second.expect_size];
            int rsize = 0;
            if (UDT::ERROR == (rsize = UDT::recv((*it).second.u,
                (*it).second.data + (*it).second.received_size,
                (*it).second.expect_size - (*it).second.received_size,
                0))) {
              if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCRCV) {
                UDT::close((*it).second.u);
                delete [] (*it).second.data;
                incoming_sockets_.erase(it);
                break;
              }
              continue;
            }
            (*it).second.received_size += rsize;
            if ((*it).second.expect_size <= (*it).second.received_size) {
              std::string message((*it).second.data, (*it).second.expect_size);
              boost::uint32_t connection_id = (*it).first;
              delete [] (*it).second.data;
              (*it).second.data = NULL;
              (*it).second.expect_size = 0;
              (*it).second.received_size = 0;
              if (HandleRendezvousMsgs(message)) {
                UDT::close((*it).second.u);
                incoming_sockets_.erase(it);
              } else {
                message_notifier_(message, connection_id);
              }
              break;
            }
          }
        }
      }
    } else {
    }
    // Deleting dead connections
    std::list<boost::uint32_t>::iterator it1;
    for (it1 = dead_connections_ids.begin(); it1 != dead_connections_ids.end();
         it1++) {
      UDT::close(incoming_sockets_[*it1].u);
      incoming_sockets_.erase(*it1);
    }
    }
  }
}

void Transport::AddIncomingConnection(UDTSOCKET u, boost::uint32_t *conn_id) {
  base::pd_scoped_lock guard(*pmutex_);
//  boost::mutex::scoped_lock gaurd(*pmutex_);
  current_id_ = base::generate_next_transaction_id(current_id_);
  struct IncomingData data = {u, 0, 0, NULL};
  // printf("id for connection = %d\n", current_id_);
  incoming_sockets_[current_id_] = data;
  *conn_id = current_id_;
}

void Transport::AddIncomingConnection(UDTSOCKET u) {
  base::pd_scoped_lock guard(*pmutex_);
//  boost::mutex::scoped_lock gaurd(*pmutex_);
  current_id_ = base::generate_next_transaction_id(current_id_);
  struct IncomingData data = {u, 0, 0, NULL};
  // printf("id for connection = %d\n", current_id_);
  incoming_sockets_[current_id_] = data;
}

void Transport::CloseConnection(boost::uint32_t connection_id) {
  base::pd_scoped_lock gaurd(*pmutex_);
//  boost::mutex::scoped_lock gaurd(*pmutex_);
  std::map<boost::uint32_t, IncomingData>::iterator it;
  it = incoming_sockets_.find(connection_id);
  if (it != incoming_sockets_.end()) {
    if (incoming_sockets_[connection_id].data != NULL)
      delete [] incoming_sockets_[connection_id].data;
    UDT::close(incoming_sockets_[connection_id].u);
    incoming_sockets_.erase(connection_id);
  }
}
bool Transport::ConnectionExists(boost::uint32_t connection_id) {
  std::map<boost::uint32_t, IncomingData>::iterator it;
  base::pd_scoped_lock gaurd(*pmutex_);
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
      base::pd_scoped_lock gaurd(*pmutex_);
      if (stop_) return;
    }
    std::list<OutgoingData>::iterator it;
    {
      boost::mutex::scoped_lock guard(out_mutex_);
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
      const uint16_t &peer_port) {
  UDT::setsockopt(*skt, 0, UDT_RCVSYN, new bool(false), sizeof(bool));  // NOLINT
  UDT::setsockopt(*skt, 0, UDT_REUSEADDR, new bool(true), sizeof(bool));  // NOLINT

  *skt = UDT::socket(addrinfo_res_->ai_family, addrinfo_res_->ai_socktype,
    addrinfo_res_->ai_protocol);
  if (UDT::ERROR == UDT::bind(*skt, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
    printf("Bind error: %s\n", UDT::getlasterror().getErrorMessage());
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
    printf("remote ip %s", peer_address.c_str());
    printf("bad address\n");
    return false;
  }
  printf("remote address %s:%d\n", peer_address.c_str(), peer_port);
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
    Send(msg.ip(), msg.port(),"", 0, ser_msg, STRING, &conn_id, false);
  } else if (msg.type() == FORWARD_MSG) {
    UDTSOCKET skt;
    if (Connect(&skt, msg.ip(), msg.port())) {
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
    boost::mutex::scoped_lock lock(ping_rendez_mutex_);
    directly_connected_ = directly_connected;
    ping_rendezvous_ = true;
    cond_.notify_one();
  }
}

void Transport::PingHandle() {
  while (true) {
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      while (!ping_rendezvous_) {
        cond_.wait(lock);
      }
    }
    {
      base::pd_scoped_lock gaurd(*pmutex_);
      if (stop_) return;
    }
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      if (directly_connected_) return;
    }
    UDTSOCKET skt;
    if (Connect(&skt, my_rendezvous_ip_, my_rendezvous_port_)) {
      UDT::close(skt);
      bool dead_rendezvous_server = false;
      // it is not dead, no nead to return the ip and port
      rendezvous_notifier_(dead_rendezvous_server, "", 0);
      boost::this_thread::sleep(boost::posix_time::seconds(8));
    } else {
      {
        boost::mutex::scoped_lock lock(ping_rendez_mutex_);
        ping_rendezvous_ = false;
      }
      // check in case Stop was called before timeout of connection, then
      // there is no need to call rendezvous_notifier_
      {
      base::pd_scoped_lock gaurd(*pmutex_);
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
  if (Connect(&skt, ip, port))
    result = true;
  UDT::close(skt);
  return result;
}
};  // namespace transport
