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
      req_mutex_(),
      channels_mutex_(),
      id_mutex_(),
      current_request_id_(0),
      channels_(),
      pending_req_(),
      external_port_(0),
      external_ip_(""),
      routingtable_() {}

ChannelManagerImpl::~ChannelManagerImpl() {
  if (is_started) {
    StopTransport();
  }
  channels_.clear();
  pending_req_.clear();
}

void ChannelManagerImpl::AddPendingRequest(const boost::uint32_t &req_id,
      PendingReq req) {
  if (!is_started) {
    return;
  }
  boost::mutex::scoped_lock guard(req_mutex_);
  pending_req_[req_id] = req;
}

void ChannelManagerImpl::AddReqToTimer(const boost::uint32_t &req_id,
    const int &timeout) {
  if (!is_started) {
    return;
  }
  ptimer_->AddCallLater(timeout,
      boost::bind(&ChannelManagerImpl::TimerHandler, this, req_id));
}

boost::uint32_t ChannelManagerImpl::CreateNewId() {
  boost::mutex::scoped_lock guard(id_mutex_);
  current_request_id_ = base::generate_next_transaction_id(current_request_id_);
  return current_request_id_;
}

void ChannelManagerImpl::DeleteRequest(const boost::uint32_t &req_id) {
  boost::mutex::scoped_lock guard(req_mutex_);
  pending_req_.erase(req_id);
}

void ChannelManagerImpl::RegisterChannel(const std::string &service_name,
                                     Channel* channel) {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_[service_name] = channel;
}

int ChannelManagerImpl::StartTransport(boost::uint16_t port,
    boost::function<void(const bool&, const std::string&,
                         const boost::uint16_t&)> notify_dead_server) {
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
    count_++;
    try_port_ = ((port + count_) % (kMaxPort - kMinPort + 1)) + kMinPort;
  }
  external_port_ = try_port_;
  routingtable_ = std::auto_ptr<base::PDRoutingTableHandler>(
    new base::PDRoutingTableHandler(base::itos(external_port_)));
  return start_res_;
}

int ChannelManagerImpl::StopTransport() {
  if (!is_started) {
    return 0;
  }
  is_started = false;
  ptimer_->CancelAll();
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::StopTransport() on port ");
  printf("%i, before ptransport_->Stop().\n", external_port_);
#endif
  ptransport_->Stop();
#ifdef VERBOSE_DEBUG
  printf("\tIn ChannelManager::StopTransport(), after ptransport_->Stop().\n");
#endif
  routingtable_->Clear();
  return 1;
}

void ChannelManagerImpl::CleanUpTransport() {
  UDT::cleanup();
}

void ChannelManagerImpl::MessageArrive(const RpcMessage &msg,
    const boost::uint32_t &connection_id) {
  RpcMessage decoded_msg = msg;
  if (decoded_msg.rpc_type() == REQUEST) {
    if (!decoded_msg.has_service() || !decoded_msg.has_method()) {
#ifdef DEBUG
    printf("%d --- request arrived cannot parse message\n", external_port_);
#endif
      return;
    }
    // If this is a special find node for boostrapping,
    // inject incoming address
    if (decoded_msg.method() == "Bootstrap") {
      kad::BootstrapRequest decoded_bootstrap;
      if (!decoded_bootstrap.ParseFromString(decoded_msg.args())) {
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
        return;
      }
      decoded_msg.set_args(encoded_bootstrap);
    }
    // Find Channel that has registered the service
    std::map<std::string, Channel*>::iterator it;
    channels_mutex_.lock();
    it = channels_.find(decoded_msg.service());
    if (it != channels_.end()) {
#ifdef DEBUG
      printf("%i -- Calling HandleRequest for req -- %i\n",
          external_port_, decoded_msg.message_id());
#endif
      channels_[decoded_msg.service()]->HandleRequest(decoded_msg,
                                                      connection_id);
      channels_mutex_.unlock();
#ifdef DEBUG
      printf("%i -- After Handling Request -- %i\n",
          external_port_, decoded_msg.message_id());
#endif
    } else {
#ifdef VERBOSE_DEBUG
      printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
             external_port_,
             connection_id);
      printf("service not registered.\n");
#endif
      channels_mutex_.unlock();
    }
  } else if (decoded_msg.rpc_type() == RESPONSE) {
    std::map<boost::uint32_t, PendingReq>::iterator it;
    req_mutex_.lock();
#ifdef DEBUG
    printf("%d --- response arrived for %s  -- %d\n", external_port_,
      decoded_msg.method().c_str(), decoded_msg.message_id());
#endif
    it = pending_req_.find(decoded_msg.message_id());
    if (it != pending_req_.end()) {
      google::protobuf::Message* response =
          pending_req_[decoded_msg.message_id()].args;
      if (response->ParseFromString(decoded_msg.args())) {
        google::protobuf::Closure* done =
            pending_req_[decoded_msg.message_id()].callback;
        pending_req_.erase(decoded_msg.message_id());
        req_mutex_.unlock();
#ifdef DEBUG
        printf("%i -- ChannelManager --- Executing Callback msg arrived %i \n",
           external_port_, decoded_msg.message_id());
#endif
        done->Run();
#ifdef DEBUG
        printf("ChannelManager --- After executing Callback (done->Run ())\n");
#endif
        ptransport_->CloseConnection(connection_id);
      } else {
        req_mutex_.unlock();
#ifdef DEBUG
        printf("%i -- ChannelManager no callback for id %i\n", external_port_,
            decoded_msg.message_id());
#endif
      }
    } else {
      req_mutex_.unlock();
#ifdef DEBUG
        printf("%i -- ChannelManager no request for id %i\n", external_port_,
            decoded_msg.message_id());
#endif
    }
  } else {
#ifdef VERBOSE_DEBUG
    printf("\tIn ChannelManager::MessageArrive(%i - %i), ",
           external_port_,
           connection_id);
    printf("unknown type of message received. \n");
#endif
  }
}

void ChannelManagerImpl::TimerHandler(const boost::uint32_t &req_id) {
  if (!is_started) {
    return;
  }
  std::map<boost::uint32_t, PendingReq>::iterator it;
  req_mutex_.lock();
  it = pending_req_.find(req_id);
  if (it != pending_req_.end()) {
    boost::uint32_t connection_id = pending_req_[req_id].connection_id;
    int timeout = pending_req_[req_id].timeout;
    if (ptransport_->HasReceivedData(connection_id)) {
      req_mutex_.unlock();
      printf("reseting timeout\n");
      AddReqToTimer(req_id, timeout);
    } else {
#ifdef DEBUG
      printf("transport %d Request times out. RPC ID: %d. Connection ID: %d.\n",
             ptransport_->listening_port(),
             req_id,
             pending_req_[req_id].connection_id);
#endif
      // call back without modifying the response
      google::protobuf::Closure* done = pending_req_[req_id].callback;
      pending_req_.erase(req_id);
      req_mutex_.unlock();
      printf("%i -- executing request after timeout. id = %i\n",
        external_port_, req_id);
      done->Run();
      printf("%i -- executed request after timeout. id = %i\n",
        external_port_, req_id);
      if (connection_id != 0)
        ptransport_->CloseConnection(connection_id);
    }
  } else {
    req_mutex_.unlock();
  }
}

void ChannelManagerImpl::UnRegisterChannel(const std::string &service_name) {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_.erase(service_name);
}

void ChannelManagerImpl::ClearChannels() {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_.clear();
}

void ChannelManagerImpl::ClearCallLaters() {
  boost::mutex::scoped_lock guard(req_mutex_);
  ptimer_->CancelAll();
  pending_req_.clear();
}

bool ChannelManagerImpl::CheckConnection(const std::string &ip,
    const uint16_t &port) {
  if (!is_started)
    return false;
  std::string dec_lip;
  if (ip.size() == 4) {
    dec_lip = base::inet_btoa(ip);
  } else {
    dec_lip = ip;
  }
  return ptransport_->CanConnect(dec_lip, port);
}

bool ChannelManagerImpl::CheckLocalAddress(const std::string &local_ip,
    const std::string &remote_ip, const uint16_t &remote_port) {
  return ptransport_->CheckConnection(local_ip, remote_ip, remote_port);
}
}
