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

#include "rpcprotocol/channelmanagerimpl.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "protobuf/rpcmessage.pb.h"

namespace rpcprotocol {

ChannelManagerImpl::ChannelManagerImpl()
    : ptransport_(new transport::Transport()),
      is_started(false),
      ptimer_(new base::CallLaterTimer()),
      mutex_(),
      current_request_id_(0),
      channels_(),
      pending_req_(),
      external_port_(0),
      external_ip_(""),
      routingtable_() {
  for (int i = 0; i < 8; ++i) {
    boost::shared_ptr<boost::mutex> mutex(new boost::mutex);
    mutex_.push_back(mutex);
  }
}

ChannelManagerImpl::~ChannelManagerImpl() {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (on port %i) destructor.\n", external_port_);
#endif
  if (is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager (on port %i) destructor, stopping transport.\n",
           external_port_);
#endif
    StopTransport();
#ifdef VERBOSE_DEBUG
  } else {
    printf("\tIn ChannelManager (on port %i) destructor, already stopped.\n",
           external_port_);
#endif
  }
  channels_.clear();
  pending_req_.clear();
}

void ChannelManagerImpl::AddPendingRequest(const boost::uint32_t &req_id,
      PendingReq req) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) AddPendingRequest %i\n",
         external_port_,
         req_id);
#endif
  boost::mutex::scoped_lock guard(*mutex_[0]);
  if (!is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager (%i) AddPendingRequest - not started.\n",
           external_port_);
#endif
    return;
  }
  pending_req_[req_id] = req;
}

void ChannelManagerImpl::AddReqToTimer(const boost::uint32_t &req_id,
    const int &timeout) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) AddReqToTimer %i\n",
         external_port_,
         req_id);
#endif
  boost::mutex::scoped_lock guard(*mutex_[1]);
  if (!is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager (%i) AddReqToTimer - not started.\n",
           external_port_);
#endif
    return;
  }
  ptimer_->AddCallLater(timeout,
      boost::bind(&ChannelManagerImpl::TimerHandler, this, req_id));
}

boost::uint32_t ChannelManagerImpl::CreateNewId() {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) CreateNewId.\n", external_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[2]);
  current_request_id_ = base::generate_next_transaction_id(current_request_id_);
  return current_request_id_;
}

void ChannelManagerImpl::DeleteRequest(const boost::uint32_t &req_id) {
  boost::mutex::scoped_lock guard(*mutex_[3]);
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::DeleteRequest(%i) request id: %i",
         external_port_,
         req_id);
#endif
  int result = pending_req_.erase(req_id);
#ifdef VERBOSE_DEBUG
  printf(" returns result %i.\n", result);
#endif
}

void ChannelManagerImpl::RegisterChannel(const std::string &service_name,
                                     Channel* channel) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) RegisterChannel.\n", external_port_);
#endif
  channels_[service_name] = channel;
}

int ChannelManagerImpl::StartTransport(boost::uint16_t port,
    boost::function<void(const bool&, const std::string&,
                         const boost::uint16_t&)> notify_dead_server) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) StartTransport.\n", external_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[4]);
  if (is_started)
    return 0;
  int start_res_(-1);
  // if no port assigned, get a random port between 5000 & 65535 inclusive
  if (0 == port)
    port = static_cast<boost::uint16_t>
        (base::random_32bit_uinteger() % (kMaxPort - kMinPort + 1)) + kMinPort;
  current_request_id_ =
      base::generate_next_transaction_id(current_request_id_)+(port*100);
  // iterate once through ports 5000 to 65535 until success, starting at random
  // port above
  boost::uint16_t count_(0);
  boost::uint16_t try_port_ = port;
  while (count_ <= (kMaxPort - kMinPort + 1)) {
    if (0 == ptransport_->Start(try_port_,
                                boost::bind(&ChannelManagerImpl::MessageArrive,
                                            this, _1, _2),
                                notify_dead_server)) {
      start_res_ = 0;
      is_started = true;
      break;
    }
    ++count_;
    try_port_ = ((port + count_) % (kMaxPort - kMinPort + 1)) + kMinPort;
  }
  // Get local address as the external ip address...??!!
  boost::asio::ip::address local_address;
  if (base::get_local_address(&local_address)) {
    external_ip_ = local_address.to_string();
  }
  external_port_ = try_port_;
  routingtable_ = std::auto_ptr<base::PDRoutingTableHandler>(
    new base::PDRoutingTableHandler(base::itos(external_port_)));
  return start_res_;
}

int ChannelManagerImpl::StopTransport() {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) StopTransport.\n", external_port_);
#endif
  if (!is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelMangr::StopTransport() on port %i, already stopped.\n",
           external_port_);
#endif
    return 0;
  }
  is_started = false;
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelMangr::StopTransport() on port ");
  printf("%i, before ptransport_->Stop().\n", external_port_);
#endif
  ptransport_->Stop();
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::StopTransport(), after ptransport_->Stop().\n");
#endif
  routingtable_->Clear();
  return 1;
}

void ChannelManagerImpl::MessageArrive(const std::string &message,
    const boost::uint32_t &connection_id) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::MessageArrive(%i) - connection id %i.\n",
         external_port_,
         connection_id);
#endif
  boost::mutex::scoped_lock guard(*mutex_[5]);
  // decode the message
  RpcMessage decoded_msg;
  if (!decoded_msg.ParseFromString(message)) {  // ignore invalid message
    // TRI_LOG_STR("Invalid message received. ");
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::MessageArrive(%i - %i), invalid messg rec'd\n",
           external_port_,
           connection_id);
#endif
    return;
#ifdef VERBOSE_DEBUG
  } else {
    printf("\tIn ChannelManager::MessageArrive(%i - %i), message parsed OK.\n",
           external_port_,
           connection_id);
#endif
  }
  // handle the message
  if (decoded_msg.rpc_type() == REQUEST) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::MessageArrive(%i - %i), REQUEST\n",
           external_port_,
           connection_id);
#endif
    if (!decoded_msg.has_service() || !decoded_msg.has_method()) {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
             external_port_,
             connection_id);
      printf("message doesn't have required fields.\n");
#endif
      return;
    }
    // If this is a special find node for boostrapping,
    // inject incoming address
    if (decoded_msg.method() == "Bootstrap") {
      // right? what's name for find node rpc?
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
             external_port_,
             connection_id);
      printf("BOOTSTRAP.\n");
#endif
      kad::BootstrapRequest decoded_bootstrap;
      if (!decoded_bootstrap.ParseFromString(decoded_msg.args())) {
#ifdef VERBOSE_DEBUG
        printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
               external_port_,
               connection_id);
        printf("bootstrap message doesn't parse.\n");
#endif
        return;
      }
      struct sockaddr peer_addr = ptransport_->peer_address();
      std::string peer_ip(inet_ntoa(((\
        struct sockaddr_in *)&peer_addr)->sin_addr));
      boost::uint16_t peer_port =
        ntohs(((struct sockaddr_in *)&peer_addr)->sin_port);
      decoded_bootstrap.set_newcomer_ext_ip(peer_ip);
      decoded_bootstrap.set_newcomer_ext_port(peer_port);
      std::string encoded_bootstrap;
      if (!decoded_bootstrap.SerializeToString(&encoded_bootstrap)) {
#ifdef VERBOSE_DEBUG
        printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
               external_port_,
               connection_id);
        printf("couldn't serialise bootstrap reply.\n");
#endif
        return;
      }
      decoded_msg.set_args(encoded_bootstrap);
    }
    // Find Channel that has registered the service
    std::map<std::string, Channel*>::iterator it;
    it = channels_.find(decoded_msg.service());
    if (it != channels_.end()) {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
             external_port_,
             connection_id);
      printf("passing message to Channel::HandleRequest.\n");
#endif
      guard.unlock();
      channels_[decoded_msg.service()]->HandleRequest(decoded_msg,
                                                      connection_id);
    } else {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
             external_port_,
             connection_id);
      printf("service not registered.\n");
#endif
    }
//    printf("finished request -- %d\n", connection_id);
  } else if (decoded_msg.rpc_type() == RESPONSE) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::MessageArrive(%i - %i), RESPONSE\n",
           external_port_,
           connection_id);
    printf("\tIn ChannelManager::MessageArrive(%i - %i)",
           external_port_,
           connection_id);
    printf(" %s response arrived id %d \n",
           decoded_msg.method().c_str(),
           decoded_msg.message_id());
#endif
    std::map<boost::uint32_t, PendingReq>::iterator it;
    it = pending_req_.find(decoded_msg.message_id());
    if (it != pending_req_.end()) {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
             external_port_,
             connection_id);
      printf("found pending request.\n");
#endif
      google::protobuf::Message* response =
          pending_req_[decoded_msg.message_id()].args;
      if (response->ParseFromString(decoded_msg.args())) {
#ifdef VERBOSE_DEBUG
        printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
               external_port_,
               connection_id);
        printf("parsed response.\n");
#endif
        google::protobuf::Closure* done =
            pending_req_[decoded_msg.message_id()].callback;
#ifdef VERBOSE_DEBUG
        printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
               external_port_,
               connection_id);
        printf("about to delete pending request.\n");
#endif
        DeleteRequest(decoded_msg.message_id());
        // DeleteRequest(decoded_msg.message_id());
#ifdef VERBOSE_DEBUG
        printf("\tIn ChannelManager::MessageArrive(%i)", external_port_);
        printf(", connection ID: %i, closing connection\n", connection_id);
#endif
        ptransport_->CloseConnection(connection_id);
#ifdef VERBOSE_DEBUG
        printf("\tIn ChannelManager::MessageArrive(%i), closed connection %i\n",
               external_port_,
               connection_id);
        printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
               external_port_,
               connection_id);
        printf("about to call back.\n");
#endif
        guard.unlock();
        done->Run();
#ifdef VERBOSE_DEBUG
      } else {
        printf("\tIn ChannelManager::MessageArrive(%i)", external_port_);
        printf(", connection ID: %i, can't parse response.\n", connection_id);
#endif
      }
    }
  } else {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
           external_port_,
           connection_id);
    printf("unknown type of message received. \n");
#endif
    // TRI_LOG_STR("Unknown type of message received. ");
  }
}

void ChannelManagerImpl::TimerHandler(const boost::uint32_t &req_id) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::TimerHandler(%i), before mutex.\n",
         external_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[6]);
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::TimerHandler(%i), after mutex.\n",
         external_port_);
#endif
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) TimerHandler - request %i.\n",
         external_port_,
         req_id);
#endif
  // First of all, check whether the callback function is called or not, if it
  // has already been called, ignore this RPC timeout. I

  // TODO(dirvine/Haiyang): define a more reasonable time for a timeout or
  // right now it is 7 seconds for all rpc's.  In case the time for a timeout
  // is different for each rpc, then we should stored in the map or in a struct
  // to check the type of rpc to check the corresponding timeout
  // Or confirm that this is enough
  if (!is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager (%i) TimerHandler - not started.\n",
           external_port_);
    printf("\tIn ChannelManager::TimerHandler(%i), unlock 1.\n",
           external_port_);
#endif
    return;
  }
  std::map<boost::uint32_t, PendingReq>::iterator it;
  it = pending_req_.find(req_id);
  if (it != pending_req_.end()) {
#ifdef DEBUG
    printf("transport %d Request times out. RPC ID: %d. Connection ID: %d.\n",
           ptransport_->listening_port(),
           req_id,
           pending_req_[req_id].connection_id);
#endif
    // TRI_LOG_STR("Request times out. RPC ID: "<< req_id);
    // call back without modifying the response
    google::protobuf::Closure* done = pending_req_[req_id].callback;
    boost::uint32_t connection_id = pending_req_[req_id].connection_id;
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::TimerHandler(%i), before DelRequest(%i)\n",
           external_port_,
           req_id);
#endif
    DeleteRequest(req_id);
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::TimerHandler(%i), after DelRequest\n",
           external_port_);
    printf("\tIn ChannelManager::TimerHandler(%i), before done->Run()(%i)\n",
           external_port_,
           req_id);
#endif
    done->Run();
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::TimerHandler(%i), after done->Run()\n",
           external_port_);
#endif
    if (connection_id != 0) {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::TimerHandler(%i), closing req_id %i\n",
             external_port_,
             req_id);
#endif
      ptransport_->CloseConnection(connection_id);
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::TimerHandler(%i), closed connection %i\n",
             external_port_,
             connection_id);
      printf("\tIn ChannelManager::TimerHandler(%i), unlock 2.\n",
             external_port_);
#endif
      return;
    } else {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::TimerHandler(%i), error: pending requst(%i)",
             external_port_,
             req_id);
      printf(" has connection id 0\n");
      printf("\tIn ChannelManager::TimerHandler(%i), unlock 3.\n",
             external_port_);
#endif
      return;
    }
  }
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::TimerHandler(%i), request %i already deleted.\n",
         external_port_,
         req_id);
  printf("\tIn ChannelManager::TimerHandler(%i), unlock 4.\n", external_port_);
#endif
}

void ChannelManagerImpl::UnRegisterChannel(const std::string &service_name) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) UnRegisterChannel.\n", external_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[6]);
  channels_.erase(service_name);
}

void ChannelManagerImpl::ClearChannels() {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) ClearChannels.\n", external_port_);
#endif
  boost::mutex::scoped_lock guard(*mutex_[7]);
  channels_.clear();
}

void ChannelManagerImpl::AddConnectionToReq(const boost::uint32_t &req_id,
      const boost::uint32_t &conn_id) {
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager (%i) AddConnectionToReq.\n", external_port_);
#endif
  if (!is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager (%i) AddConnectionToReq - not started.\n",
           external_port_);
#endif
    return;
  }
  std::map<boost::uint32_t, PendingReq>::iterator it;
  it = pending_req_.find(req_id);
  if (it != pending_req_.end()) {
    pending_req_[req_id].connection_id = conn_id;
  }
}

bool ChannelManagerImpl::CheckConnection(const std::string &ip,
    const uint16_t &port) {
  if (!is_started) {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager (%i) CheckConnection - not started.\n",
           external_port_);
#endif
    return false;
  }
  std::string dec_lip;
  if (ip.size() == 4) {
    dec_lip = base::inet_btoa(ip);
  } else {
    dec_lip = ip;
  }
//  printf("checking connection to %s:%d\n", dec_lip.c_str(), port);
  return ptransport_->CanConnect(dec_lip, port);
}
}
