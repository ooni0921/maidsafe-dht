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
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>
#include <exception>
#include "transport/transportimpl.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/config.h"
#include "maidsafe/online.h"


namespace transport {
TransportImpl::TransportImpl() : stop_(true), message_notifier_(),
    rendezvous_notifier_(), accept_routine_(), recv_routine_(), send_routine_(),
    ping_rendz_routine_(), handle_msgs_routine_(), listening_socket_(0),
    peer_address_(), listening_port_(0), my_rendezvous_port_(0),
    my_rendezvous_ip_(""), incoming_sockets_(), outgoing_queue_(),
    incoming_msgs_queue_(), send_mutex_(), ping_rendez_mutex_(), recv_mutex_(),
    msg_hdl_mutex_(), s_skts_mutex_(), addrinfo_hints_(), addrinfo_res_(NULL),
    current_id_(0), send_cond_(), ping_rend_cond_(), recv_cond_(),
    msg_hdl_cond_(), ping_rendezvous_(false), directly_connected_(false),
    accepted_connections_(0), msgs_sent_(0), last_id_(0), data_arrived_(),
    ips_from_connections_(), send_notifier_(), send_sockets_() {
  UDT::startup();
}

TransportImpl::~TransportImpl() {
  if (!stop_)
    Stop();
}

int TransportImpl::Start(const boost::uint16_t &port,
    boost::function<void(const rpcprotocol::RpcMessage&, const boost::uint32_t&,
    const float&)> on_message, boost::function<void(const bool&,
    const std::string&, const boost::uint16_t&)> notify_dead_server,
    boost::function<void(const boost::uint32_t&, const bool&)> on_send) {
  if (!stop_)
    return 1;
  listening_port_ = port;
  memset(&addrinfo_hints_, 0, sizeof(struct addrinfo));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(port);
  if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
      &addrinfo_res_)) {
    return 1;
  }
  listening_socket_ = UDT::socket(addrinfo_res_->ai_family,
      addrinfo_res_->ai_socktype, addrinfo_res_->ai_protocol);
  // UDT Options
  bool blockng = false;
  UDT::setsockopt(listening_socket_, 0, UDT_RCVSYN, &blockng, sizeof(blockng));
  if (UDT::ERROR == UDT::bind(listening_socket_, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
    DLOG(WARNING) << "(" << listening_port_ << ") UDT bind error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_res_);
    return 1;
  }
  // Modify the port to reflect the port UDT has chosen
  struct sockaddr_in name;
  int namelen;
  if (listening_port_ == 0) {
    UDT::getsockname(listening_socket_, (struct sockaddr *)&name, &namelen);
    listening_port_ = ntohs(name.sin_port);
    std::string service = boost::lexical_cast<std::string>(listening_port_);
    freeaddrinfo(addrinfo_res_);
    if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
      &addrinfo_res_)) {
      freeaddrinfo(addrinfo_res_);
      return 1;
    }
  }

  if (UDT::ERROR == UDT::listen(listening_socket_, 20)) {
    LOG(ERROR) << "Failed to start listening port "<< listening_port_ << ": " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_res_);
    return 1;
  }
  stop_ = false;
  // start the listening loop
  try {
    accept_routine_.reset(new boost::thread(&TransportImpl::AcceptConnHandler,
        this));
    recv_routine_.reset(new boost::thread(&TransportImpl::ReceiveHandler,
        this));
    send_routine_.reset(new boost::thread(&TransportImpl::SendHandle, this));
    ping_rendz_routine_.reset(new boost::thread(&TransportImpl::PingHandle,
        this));
    handle_msgs_routine_.reset(new boost::thread(&TransportImpl::MessageHandler,
        this));
  } catch(const boost::thread_resource_error& ) {
    stop_ = true;
    int result;
    result = UDT::close(listening_socket_);
    freeaddrinfo(addrinfo_res_);
    return 1;
  }
  message_notifier_ = on_message;
  rendezvous_notifier_ = notify_dead_server;
  send_notifier_ = on_send;
  current_id_ = base::generate_next_transaction_id(current_id_);
  return 0;
}

int TransportImpl::Send(const std::string &data,
    DataType type, const boost::uint32_t &conn_id, const bool &new_skt) {

  UDTSOCKET skt;
  if (new_skt) {
    std::map<boost::uint32_t, UDTSOCKET>::iterator it;
    {
      boost::mutex::scoped_lock guard(msg_hdl_mutex_);
      it = send_sockets_.find(conn_id);
      if (it == send_sockets_.end()) {
        send_notifier_(conn_id, false);
        return 1;
      }
      skt = (*it).second;
      send_sockets_.erase(it);
    }
  } else {
    std::map<boost::uint32_t, IncomingData>::iterator it;
    {
      boost::mutex::scoped_lock guard(recv_mutex_);
      it = incoming_sockets_.find(conn_id);
      if (it == incoming_sockets_.end()) {
        send_notifier_(conn_id, false);
        return 1;
      }
      skt = (*it).second.u;
    }
  }

  if (type == STRING) {
    int64_t data_size = data.size();
    struct OutgoingData out_data = {skt, data_size, 0,
      boost::shared_array<char>(new char[data_size]), false, conn_id};
    memcpy(out_data.data.get(),
      const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
    {
      boost::mutex::scoped_lock(send_mutex_);
      outgoing_queue_.push_back(out_data);
    }
    send_cond_.notify_one();
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

void TransportImpl::Stop() {
  if (stop_)
    return;
  stop_ = true;
  if (send_routine_.get()) {
    send_cond_.notify_one();
    if (!send_routine_->timed_join(boost::posix_time::seconds(5))) {
      // forcing to interrupt the thread
      send_routine_->interrupt();
      send_routine_->join();
    }
  }
  if (accept_routine_.get()) {
    if (!accept_routine_->timed_join(boost::posix_time::seconds(5))) {
      // forcing to interrupt the thread
      accept_routine_->interrupt();
      accept_routine_->join();
    }
  }
  if (recv_routine_.get()) {
    recv_cond_.notify_one();
    if (!recv_routine_->timed_join(boost::posix_time::seconds(5))) {
      // forcing to interrupt the thread
      recv_routine_->interrupt();
      recv_routine_->join();
    }
  }
  if (ping_rendz_routine_.get()) {
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      if (!ping_rendezvous_) {
        ping_rendezvous_ = true;
      }
      ping_rend_cond_.notify_one();
    }
    if (!ping_rendz_routine_->timed_join(boost::posix_time::seconds(5))) {
      // forcing to interrupt the thread
      ping_rendz_routine_->interrupt();
      ping_rendz_routine_->join();
    }
    ping_rendezvous_ = false;
  }
  if (handle_msgs_routine_.get()) {
    msg_hdl_cond_.notify_one();
    if (!handle_msgs_routine_->timed_join(boost::posix_time::seconds(5))) {
      // forcing to interrupt the thread
      handle_msgs_routine_->interrupt();
      handle_msgs_routine_->join();
    }
  }
  UDT::close(listening_socket_);
  std::map<boost::uint32_t, IncomingData>::iterator it;
  for (it = incoming_sockets_.begin(); it != incoming_sockets_.end(); it++)
    UDT::close((*it).second.u);
  incoming_sockets_.clear();
  std::map<boost::uint32_t, UDTSOCKET>::iterator it1;
  for (it1 = send_sockets_.begin(); it1 != send_sockets_.end(); it1++) {
    UDT::close((*it1).second);
  }
  send_sockets_.clear();
  outgoing_queue_.clear();
  message_notifier_ = 0;
  send_notifier_ = 0;
  freeaddrinfo(addrinfo_res_);
  DLOG(INFO) << "(" << listening_port_ << ") Accepted connections: " <<
      accepted_connections_ << ". Msgs Sent: " << msgs_sent_ << ". Msgs Recv "
      << last_id_ << std::endl;
}

void TransportImpl::ReceiveHandler() {
  timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 1000;
  UDT::UDSET readfds;
  while (true) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    {
      boost::mutex::scoped_lock guard(recv_mutex_);
      while (incoming_sockets_.empty() && !stop_) {
        recv_cond_.wait(guard);
      }
    }
    if (stop_) return;
    // read data.
    std::list<boost::uint32_t> dead_connections_ids;
    std::map<boost::uint32_t, IncomingData>::iterator it;
    {
    boost::mutex::scoped_lock guard(recv_mutex_);
    UD_ZERO(&readfds);
    for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
        it++) {
      int res = UDT::send((*it).second.u, NULL, 0, 0);
      if (res == 0) {
        UD_SET((*it).second.u, &readfds);
      } else {
        dead_connections_ids.push_back((*it).first);
      }
    }
    }
    int res = UDT::select(0, &readfds, NULL, NULL, &tv);
    {
    boost::mutex::scoped_lock guard(recv_mutex_);
    if (res != UDT::ERROR) {
      for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
           ++it) {
        if (UD_ISSET((*it).second.u, &readfds)) {
          int result = 0;
          // save the remote peer address
          int peer_addr_size = sizeof(struct sockaddr);
          if (UDT::ERROR == UDT::getpeername((*it).second.u, &peer_address_,
              &peer_addr_size)) {
            continue;
          }
          if ((*it).second.expect_size == 0) {
            // get size information
            int64_t size;
            if (UDT::ERROR == UDT::recv((*it).second.u,
                reinterpret_cast<char*>(&size), sizeof(size), 0)) {
              if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCRCV) {
                result = UDT::close((*it).second.u);
                incoming_sockets_.erase(it);
                break;
              }
              continue;
            }
            if (size > 0) {
              (*it).second.expect_size = size;
            } else {
              result = UDT::close((*it).second.u);
              incoming_sockets_.erase(it);
              break;
            }
          } else {
            if ((*it).second.data == NULL)
              (*it).second.data = boost::shared_array<char>
                  (new char[(*it).second.expect_size]);
            int rsize = 0;
            if (UDT::ERROR == (rsize = UDT::recv((*it).second.u,
                (*it).second.data.get() + (*it).second.received_size,
                (*it).second.expect_size - (*it).second.received_size,
                0))) {
              if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCRCV) {
                result = UDT::close((*it).second.u);
                incoming_sockets_.erase(it);
                break;
              }
              continue;
            }
            (*it).second.received_size += rsize;
            UDT::TRACEINFO perf;
            if (UDT::ERROR == UDT::perfmon((*it).second.u, &perf)) {
              DLOG(ERROR) << "UDT permon error: " <<
                  UDT::getlasterror().getErrorMessage() << std::endl;
            } else {
              (*it).second.accum_RTT += perf.msRTT;
              (*it).second.observations++;
            }
            if ((*it).second.expect_size <= (*it).second.received_size) {
              ++last_id_;
              std::string message = std::string((*it).second.data.get(),
                                    (*it).second.expect_size);
              boost::uint32_t connection_id = (*it).first;
              (*it).second.expect_size = 0;
              (*it).second.received_size = 0;
              TransportMessage t_msg;
              if (t_msg.ParseFromString(message)) {
                if (t_msg.has_hp_msg()) {
                  HandleRendezvousMsgs(t_msg.hp_msg());
                  result = UDT::close((*it).second.u);
                  dead_connections_ids.push_back((*it).first);
                } else if (t_msg.has_rpc_msg()) {
                  IncomingMessages msg(connection_id);
                  msg.msg = t_msg.rpc_msg();
                  DLOG(INFO) << "(" << listening_port_ << ") message for id "
                      << connection_id << " arrived" << std::endl;
                  UDT::TRACEINFO perf;
                  if (UDT::ERROR == UDT::perfmon((*it).second.u, &perf)) {
                    DLOG(ERROR) << "UDT permon error: " <<
                        UDT::getlasterror().getErrorMessage() << std::endl;
                  } else {
                    msg.rtt = perf.msRTT;
                    if ((*it).second.observations != 0) {
                      msg.rtt = (*it).second.accum_RTT /
                          static_cast<double>((*it).second.observations);
                    } else {
                      msg.rtt = 0.0;
                    }
                  }
                  data_arrived_.insert(connection_id);
                  {  // NOLINT Fraser
                    boost::mutex::scoped_lock guard1(msg_hdl_mutex_);
                    ips_from_connections_[connection_id] = peer_address_;
                    incoming_msgs_queue_.push_back(msg);
                  }
                  msg_hdl_cond_.notify_one();
                } else {
                  LOG(WARNING) << "( " << listening_port_ <<
                      ") Invalid Message received" << std::endl;
                }
              } else {
                LOG(WARNING) << "( " << listening_port_ <<
                    ") Invalid Message received" << std::endl;
              }
            }
          }
        }
      }
    }
    // Deleting dead connections
    std::list<boost::uint32_t>::iterator it1;
    for (it1 = dead_connections_ids.begin(); it1 != dead_connections_ids.end();
         ++it1) {
      UDT::close(incoming_sockets_[*it1].u);
      incoming_sockets_.erase(*it1);
    }
    }
  }
}

void TransportImpl::AddIncomingConnection(UDTSOCKET u,
      boost::uint32_t *conn_id) {
  {
    boost::mutex::scoped_lock guard(recv_mutex_);
    current_id_ = base::generate_next_transaction_id(current_id_);
    struct IncomingData data = {u, 0, 0, boost::shared_array<char>(NULL), 0, 0};
    incoming_sockets_[current_id_] = data;
    *conn_id = current_id_;
  }
  recv_cond_.notify_one();
}

void TransportImpl::AddIncomingConnection(UDTSOCKET u) {
  {
    boost::mutex::scoped_lock guard(recv_mutex_);
    current_id_ = base::generate_next_transaction_id(current_id_);
    struct IncomingData data = {u, 0, 0, boost::shared_array<char>(NULL), 0, 0};
    incoming_sockets_[current_id_] = data;
  }
  recv_cond_.notify_one();
}

void TransportImpl::CloseConnection(const boost::uint32_t &connection_id) {
  std::map<boost::uint32_t, IncomingData>::iterator it;
  boost::mutex::scoped_lock guard(recv_mutex_);
  it = incoming_sockets_.find(connection_id);
  if (it != incoming_sockets_.end()) {
    UDT::close(incoming_sockets_[connection_id].u);
    incoming_sockets_.erase(connection_id);
    data_arrived_.erase(connection_id);
  }
}

bool TransportImpl::ConnectionExists(const boost::uint32_t &connection_id) {
  std::map<boost::uint32_t, IncomingData>::iterator it;
  boost::mutex::scoped_lock guard(recv_mutex_);
  it = incoming_sockets_.find(connection_id);
  if (it != incoming_sockets_.end()) {
    return true;
  } else {
    return false;
  }
}

bool TransportImpl::HasReceivedData(const boost::uint32_t &connection_id,
    int64_t *size) {
  std::map<boost::uint32_t, IncomingData>::iterator it1;
  std::set<boost::uint32_t>::iterator it2;
  bool result = false;
  boost::mutex::scoped_lock guard(recv_mutex_);
  it1 = incoming_sockets_.find(connection_id);
  if (it1 != incoming_sockets_.end()) {
    if ((*it1).second.received_size > *size) {
      *size = (*it1).second.received_size;
      result = true;
    } else {
      it2 = data_arrived_.find(connection_id);
      if (it2 != data_arrived_.end()) {
        result = true;
      } else {
        result = false;
      }
    }
  } else {
    it2 = data_arrived_.find(connection_id);
    if (it2 != data_arrived_.end()) {
      result = true;
    } else {
      result = false;
    }
  }
  return result;
}

void TransportImpl::SendHandle() {
  while (true) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    {
      boost::mutex::scoped_lock guard(send_mutex_);
      while (outgoing_queue_.empty() && !stop_) {
        send_cond_.wait(guard);
      }
    }
    if (stop_)
      return;
    std::list<OutgoingData>::iterator it;
    {
      boost::mutex::scoped_lock guard(send_mutex_);
      for (it = outgoing_queue_.begin(); it != outgoing_queue_.end(); it++) {
        if (!it->sent_size) {
          if (UDT::ERROR == UDT::send(it->u,
              reinterpret_cast<char*>(&it->data_size), sizeof(int64_t), 0)) {
            if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCSND) {
              DLOG(ERROR) << "(" << listening_port_ <<
                  ") Error sending message size: " <<
                  UDT::getlasterror().getErrorMessage() << std::endl;
              send_notifier_(it->conn_id, false);
              outgoing_queue_.erase(it);
              break;
            }
            continue;
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
            if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCSND) {
              DLOG(ERROR) << "(" << listening_port_ <<
                  ") Error sending message data: " <<
                  UDT::getlasterror().getErrorMessage() << std::endl;
              send_notifier_(it->conn_id, false);
              outgoing_queue_.erase(it);
              break;
            }
            continue;
          }
          it->data_sent += ssize;
        } else {
          // Finished sending data
          send_notifier_(it->conn_id, true);
          outgoing_queue_.erase(it);
          msgs_sent_++;
          break;
        }
      }
    }  // lock scope end here
  }
}

int TransportImpl::Connect(UDTSOCKET *skt, const std::string &peer_address,
      const uint16_t &peer_port, bool) {
  if (stop_)
    return -1;
  bool blocking = false;
  bool reuse_addr = true;
  UDT::setsockopt(*skt, 0, UDT_RCVSYN, &blocking, sizeof(blocking));
  UDT::setsockopt(*skt, 0, UDT_SNDSYN, &blocking, sizeof(blocking));
  UDT::setsockopt(*skt, 0, UDT_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

  *skt = UDT::socket(addrinfo_res_->ai_family, addrinfo_res_->ai_socktype,
    addrinfo_res_->ai_protocol);
  if (UDT::ERROR == UDT::bind(*skt, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
    LOG(ERROR) << "(" << listening_port_ << ") UDT Bind error: " <<
        UDT::getlasterror().getErrorMessage()<< std::endl;
    return -1;
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
    LOG(ERROR) << "Invalid remote address " << peer_address << ":"<< peer_port
        << std::endl;
    return -1;
  }
  if (UDT::ERROR == UDT::connect(*skt, reinterpret_cast<sockaddr*>(&peer_addr),
      sizeof(peer_addr))) {
    LOG(ERROR) << "(" << listening_port_ << ") UDT connect to " << peer_address
        << ":" << peer_port << " -- " << UDT::getlasterror().getErrorMessage()
        << std::endl;
    return UDT::getlasterror().getErrorCode();
  }
  return 0;
}

void TransportImpl::HandleRendezvousMsgs(const HolePunchingMsg &message) {
  if (message.type() == FORWARD_REQ) {
    TransportMessage t_msg;
    HolePunchingMsg *forward_msg = t_msg.mutable_hp_msg();
    std::string peer_ip(inet_ntoa(((\
      struct sockaddr_in *)&peer_address_)->sin_addr));
    boost::uint16_t peer_port =
      ntohs(((struct sockaddr_in *)&peer_address_)->sin_port);
    forward_msg->set_ip(peer_ip);
    forward_msg->set_port(peer_port);
    forward_msg->set_type(FORWARD_MSG);
    std::string ser_msg;
    t_msg.SerializeToString(&ser_msg);
    boost::uint32_t conn_id;
    if (0 == ConnectToSend(message.ip(), message.port(), "", 0, "", 0, false,
                           &conn_id))
      Send(ser_msg, STRING, conn_id, true);
  } else if (message.type() == FORWARD_MSG) {
    UDTSOCKET skt;
    if (Connect(&skt, message.ip(), message.port(), true) == 0) {
      UDT::close(skt);
    }
  }
}

void TransportImpl::StartPingRendezvous(const bool &directly_connected,
      const std::string &my_rendezvous_ip, const boost::uint16_t
      &my_rendezvous_port) {
  my_rendezvous_port_ = my_rendezvous_port;
  if (my_rendezvous_ip.length() == 4)
    my_rendezvous_ip_ = base::inet_btoa(my_rendezvous_ip);
  else
    my_rendezvous_ip_ = my_rendezvous_ip;
  {
    boost::mutex::scoped_lock lock(ping_rendez_mutex_);
    directly_connected_ = directly_connected;
    ping_rendezvous_ = true;
  }
  ping_rend_cond_.notify_one();
}

void TransportImpl::StopPingRendezvous() {
  boost::mutex::scoped_lock guard(ping_rendez_mutex_);
  ping_rendezvous_ = false;
}

void TransportImpl::PingHandle() {
  while (true) {
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      while (!ping_rendezvous_) {
        ping_rend_cond_.wait(lock);
      }
    }
    if (stop_) return;
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      if (directly_connected_) return;
    }
    UDTSOCKET skt;

    if (Connect(&skt, my_rendezvous_ip_, my_rendezvous_port_, false) == 0) {
      UDT::close(skt);
      bool dead_rendezvous_server = false;
      // it is not dead, no nead to return the ip and port
      rendezvous_notifier_(dead_rendezvous_server, "", 0);
      boost::this_thread::sleep(boost::posix_time::seconds(8));
    } else {
      // retrying two more times to connect to make sure
      // two seconds between each ping
      bool alive = false;
      for (int i = 0; i < 2 && !alive; i++) {
        boost::this_thread::sleep(boost::posix_time::seconds(2));
        if (Connect(&skt, my_rendezvous_ip_, my_rendezvous_port_, false) == 0) {
          UDT::close(skt);
          alive = true;
        }
      }
      if (!alive) {
        {
          boost::mutex::scoped_lock lock(ping_rendez_mutex_);
          ping_rendezvous_ = false;
        }
        base::OnlineController::instance()->SetOnline(listening_port_, false);
        // check in case Stop was called before timeout of connection, then
        // there is no need to call rendezvous_notifier_
        if (stop_) return;
        bool dead_rendezvous_server = true;
        rendezvous_notifier_(dead_rendezvous_server, my_rendezvous_ip_,
          my_rendezvous_port_);
      } else {
        base::OnlineController::instance()->SetOnline(listening_port_, true);
        bool dead_rendezvous_server = false;
        rendezvous_notifier_(dead_rendezvous_server, "", 0);
        boost::this_thread::sleep(boost::posix_time::seconds(8));
      }
    }
  }
}

bool TransportImpl::CanConnect(const std::string &ip, const uint16_t &port) {
  UDTSOCKET skt;
  bool result = false;
  if (Connect(&skt, ip, port, false) == 0)
    result = true;
  UDT::close(skt);
  return result;
}

void TransportImpl::AcceptConnHandler() {
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  UDTSOCKET recver;
  while (true) {
    if (stop_) return;
    if (UDT::INVALID_SOCK == (recver = UDT::accept(listening_socket_,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen))) {
      if (UDT::getlasterror().getErrorCode() == CUDTException::EASYNCRCV) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(10));
        continue;
      } else {
        DLOG(ERROR) << "(" << listening_port_ << ") UDT::accept error: " <<
            UDT::getlasterror().getErrorMessage() << std::endl;
        return;
      }
    }
    sockaddr peer_addr;
    int peer_addr_size = sizeof(struct sockaddr);
    if (UDT::ERROR != UDT::getpeername(recver, &peer_addr, &peer_addr_size)) {
      accepted_connections_++;
      AddIncomingConnection(recver);
    } else {
      UDT::close(recver);
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
}

void TransportImpl::MessageHandler() {
  while (true) {
    {
      {
        boost::mutex::scoped_lock guard(msg_hdl_mutex_);
        while (incoming_msgs_queue_.empty() && !stop_) {
          msg_hdl_cond_.wait(guard);
        }
      }
      if (stop_) return;
      IncomingMessages msg;
      {
        boost::mutex::scoped_lock guard(msg_hdl_mutex_);
        msg.msg = incoming_msgs_queue_.front().msg;
        msg.conn_id = incoming_msgs_queue_.front().conn_id;
        msg.rtt = incoming_msgs_queue_.front().rtt;
        incoming_msgs_queue_.pop_front();
      }
      {
        boost::mutex::scoped_lock gaurd(recv_mutex_);
        data_arrived_.erase(msg.conn_id);
      }
      message_notifier_(msg.msg, msg.conn_id, msg.rtt);
      ips_from_connections_.erase(msg.conn_id);
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    }
  }
}

int TransportImpl::Send(const rpcprotocol::RpcMessage &data,
    const boost::uint32_t &conn_id, const bool &new_skt) {
  TransportMessage msg;
  rpcprotocol::RpcMessage *rpc_msg = msg.mutable_rpc_msg();
  *rpc_msg = data;
  if (data.IsInitialized()) {
    std::string ser_msg;
    msg.SerializeToString(&ser_msg);
    return Send(ser_msg, STRING, conn_id, new_skt);
  } else {
    {
      boost::mutex::scoped_lock guard(msg_hdl_mutex_);
      std::map<boost::uint32_t, UDTSOCKET>::iterator it =
          send_sockets_.find(conn_id);
      if (it != send_sockets_.end())
        send_sockets_.erase(it);
    }
    return 1;
  }
}

bool TransportImpl::CheckConnection(const std::string &local_ip,
      const std::string &remote_ip, const uint16_t &remote_port) {
  struct addrinfo hints, *local;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (0 != getaddrinfo(local_ip.c_str(), "0", &hints, &local)) {
    LOG(ERROR) << "Invalid local address " << local_ip << std::endl;
    return false;
  }

  UDTSOCKET skt = UDT::socket(local->ai_family, local->ai_socktype,
                              local->ai_protocol);
  if (UDT::ERROR == UDT::bind(skt, local->ai_addr, local->ai_addrlen)) {
    LOG(ERROR) << "(" << listening_port_ << ") UDT Bind error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return false;
  }

  freeaddrinfo(local);
  sockaddr_in remote_addr;
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_port = htons(remote_port);

#ifndef WIN32
  if (inet_pton(AF_INET, remote_ip.c_str(), &remote_addr.sin_addr) <= 0) {
    DLOG(ERROR) << "Invalid remote address " << remote_ip << ":"<< remote_port
        << std::endl;
    return false;
  }
#else
  if (INADDR_NONE == (remote_addr.sin_addr.s_addr =
      inet_addr(remote_ip.c_str()))) {
    DLOG(ERROR) << "Invalid remote address " << remote_ip << ":"<< remote_port
        << std::endl;
    return false;
  }
#endif

  if (UDT::ERROR == UDT::connect(skt,
      reinterpret_cast<sockaddr*>(&remote_addr), sizeof(remote_addr))) {
    DLOG(ERROR) << "(" << listening_port_ << ") UDT connect to " << remote_ip
        << ":" << remote_port <<" -- " << UDT::getlasterror().getErrorMessage()
        << std::endl;
    return false;
  }
  UDT::close(skt);
  return true;
}

bool TransportImpl::GetPeerAddr(const boost::uint32_t &conn_id,
    struct sockaddr *addr) {
  std::map<boost::uint32_t, struct sockaddr>::iterator it;
  it = ips_from_connections_.find(conn_id);
  if (it == ips_from_connections_.end())
    return false;
  *addr = ips_from_connections_[conn_id];
  return true;
}

int TransportImpl::ConnectToSend(const std::string &remote_ip,
    const uint16_t &remote_port, const std::string &local_ip,
    const uint16_t &local_port, const std::string &rendezvous_ip,
    const uint16_t &rendezvous_port, const bool &keep_connection,
    boost::uint32_t *conn_id) {
  UDTSOCKET skt;
  // the node receiver is directly connected, no rendezvous information
  if (rendezvous_ip == "" && rendezvous_port == 0) {
    bool remote(local_ip == "" || local_port == 0);
    // the node is believed to be local
    if (!remote) {
      int conn_result = Connect(&skt, local_ip, local_port, false);
      if (conn_result != 0) {
        DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend "
            << "failed to connect to local port " << local_port <<
            " with udp error " << conn_result << std::endl;
        UDT::close(skt);
        remote = true;
        base::PDRoutingTable::getInstance()[base::itos(listening_port_)]->
            UpdateLocalToUnknown(local_ip, local_port);
      }
    }
    if (remote) {
      int conn_result = Connect(&skt, remote_ip, remote_port, false);
      if (conn_result != 0) {
        DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend "
            << "failed to connect to remote port" << remote_port << std::endl;
        UDT::close(skt);
        return conn_result;
      }
    }
  } else {
    UDTSOCKET rend_skt;
    int conn_result = Connect(&rend_skt, rendezvous_ip, rendezvous_port, false);
    if (conn_result != 0) {
      DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend " <<
          "failed to connect to rendezvouz port " << rendezvous_port <<
          std::endl;
      UDT::close(rend_skt);
      return conn_result;
    }
    TransportMessage t_msg;
    HolePunchingMsg *msg = t_msg.mutable_hp_msg();
    msg->set_ip(remote_ip);
    msg->set_port(remote_port);
    msg->set_type(FORWARD_REQ);
    std::string ser_msg;
    t_msg.SerializeToString(&ser_msg);
    int64_t rend_data_size = ser_msg.size();

    // send rendezvous msg size information
    if (UDT::ERROR == UDT::send(rend_skt,
        reinterpret_cast<char*>(&rend_data_size),
        sizeof(rend_data_size), 0)) {
      UDT::close(rend_skt);
      return 1;
    }

    if (UDT::ERROR == UDT::send(rend_skt, ser_msg.c_str(), rend_data_size, 0)) {
      UDT::close(rend_skt);
      return 1;
    }
    // TODO(jose): establish connect in a thread or in another asynchronous
    // way to avoid blocking in the upper layers
    int retries = 4;
    bool connected = false;
    for (int i = 0; i < retries && !connected; i++) {
      conn_result = Connect(&skt, remote_ip, remote_port, false);
      if (conn_result == 0)
        connected = true;
    }
    if (!connected) {
      DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend " <<
          "failed to connect to remote port " << remote_port << std::endl;
      UDT::close(skt);
      return conn_result;
    }
  }
  if (keep_connection) {
    AddIncomingConnection(skt, conn_id);
  } else  {
    current_id_ = base::generate_next_transaction_id(current_id_);
    *conn_id = current_id_;
  }
  {
    boost::mutex::scoped_lock guard(msg_hdl_mutex_);
    send_sockets_[*conn_id] = skt;
  }
  return 0;
}

int TransportImpl::StartLocal(const boost::uint16_t &port,
      boost::function <void(const rpcprotocol::RpcMessage&,
        const boost::uint32_t&, const float &)> on_message,
      boost::function<void(const boost::uint32_t&, const bool&)> on_send) {
  if (!stop_)
    return 1;
  listening_port_ = port;
  memset(&addrinfo_hints_, 0, sizeof(struct addrinfo));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(port);
  if (0 != getaddrinfo("127.0.0.1", service.c_str(), &addrinfo_hints_,
      &addrinfo_res_)) {
    return 1;
  }
  listening_socket_ = UDT::socket(addrinfo_res_->ai_family,
      addrinfo_res_->ai_socktype, addrinfo_res_->ai_protocol);
  // UDT Options
  bool blockng = false;
  UDT::setsockopt(listening_socket_, 0, UDT_RCVSYN, &blockng, sizeof(blockng));
  if (UDT::ERROR == UDT::bind(listening_socket_, addrinfo_res_->ai_addr,
      addrinfo_res_->ai_addrlen)) {
    LOG(ERROR) << "Error binding listening socket" <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_res_);
    return 1;
  }
  // Modify the port to reflect the port UDT has chosen
  struct sockaddr_in name;
  int namelen;
  if (listening_port_ == 0) {
    UDT::getsockname(listening_socket_, (struct sockaddr *)&name, &namelen);
    listening_port_ = ntohs(name.sin_port);
        UDT::getsockname(listening_socket_, (struct sockaddr *)&name, &namelen);
    listening_port_ = ntohs(name.sin_port);
    std::string service = boost::lexical_cast<std::string>(listening_port_);
    freeaddrinfo(addrinfo_res_);
    if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
      &addrinfo_res_)) {
      freeaddrinfo(addrinfo_res_);
      return 1;
    }
  }

  if (UDT::ERROR == UDT::listen(listening_socket_, 20)) {
    LOG(ERROR) << "Failed to start the listening socket " << listening_socket_
        << " : " << UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_res_);
    return 1;
  }
  stop_ = false;
  // start the listening loop
  try {
    accept_routine_.reset(new boost::thread(&TransportImpl::AcceptConnHandler,
        this));
    recv_routine_.reset(new boost::thread(&TransportImpl::ReceiveHandler,
        this));
    send_routine_.reset(new boost::thread(&TransportImpl::SendHandle, this));
    handle_msgs_routine_.reset(new boost::thread(&TransportImpl::MessageHandler,
        this));
  } catch(const boost::thread_resource_error& ) {
    stop_ = true;
    int result;
    result = UDT::close(listening_socket_);
    freeaddrinfo(addrinfo_res_);
    return 1;
  }
  message_notifier_ = on_message;
  send_notifier_ = on_send;
  current_id_ = base::generate_next_transaction_id(current_id_);
  return 0;
}

void TransportImpl::CleanUp() {
  UDT::cleanup();
}

bool TransportImpl::IsPortAvailable(const boost::uint16_t &port) {
  struct addrinfo addrinfo_hints;
  struct addrinfo* addrinfo_res;
  memset(&addrinfo_hints, 0, sizeof(struct addrinfo));
  addrinfo_hints.ai_flags = AI_PASSIVE;
  addrinfo_hints.ai_family = AF_INET;
  addrinfo_hints.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(port);
  if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints,
      &addrinfo_res)) {
    freeaddrinfo(addrinfo_res);
    return false;
  }
  UDTSOCKET skt = UDT::socket(addrinfo_res->ai_family,
      addrinfo_res->ai_socktype, addrinfo_res->ai_protocol);
  if (UDT::ERROR == UDT::bind(skt, addrinfo_res->ai_addr,
      addrinfo_res->ai_addrlen)) {
    freeaddrinfo(addrinfo_res);
    return false;
  }
  if (UDT::ERROR == UDT::listen(skt, 20)) {
    freeaddrinfo(addrinfo_res);
    return false;
  }
  UDT::close(skt);
  freeaddrinfo(addrinfo_res);
  return true;
}
};  // namespace transport
