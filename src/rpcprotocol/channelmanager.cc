/*
Copyright (c) 2009 maidsafe.net lmited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 *  Created on: Feb 12, 2009
 *      Author: Jose
 */
#include "rpcprotocol/channelmanager.h"
#include "base/tri_logger.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "config.h"
// TODO(David Irvine<david.irvine@maidsafe.net>):
// This should not be here API leakage !

namespace rpcprotocol {

ChannelManager::ChannelManager(base::CallLaterTimer *timer,
      boost::recursive_mutex *mutex)
    : ptransport_(new transport::Transport(mutex)),
      is_started(false),
      ptimer_(timer),
      pmutex_(mutex),
      current_request_id_(0),
      channels_(),
      pending_req_(),
      external_port_(0),
      external_ip_(),
      routingtable_() {}

ChannelManager::~ChannelManager() {
  if (is_started)
    StopTransport();
  channels_.clear();
  pending_req_.clear();
  delete ptransport_;
}

void ChannelManager::AddPendingRequest(const boost::uint32_t &req_id,
      PendingReq req) {
  base::pd_scoped_lock guard(*pmutex_);
  pending_req_[req_id] = req;
}

void ChannelManager::AddReqToTimer(const boost::uint32_t &req_id,
    const int &timeout) {
  base::pd_scoped_lock guard(*pmutex_);
  ptimer_->AddCallLater(timeout,
      boost::bind(&ChannelManager::TimerHandler, this, req_id));
}

boost::uint32_t ChannelManager::CreateNewId() {
  base::pd_scoped_lock guard(*pmutex_);
  current_request_id_ = base::generate_next_transaction_id(current_request_id_);
  return current_request_id_;
}

void ChannelManager::DeleteRequest(const boost::uint32_t &req_id) {
  base::pd_scoped_lock gaurd(*pmutex_);
  pending_req_.erase(req_id);
}

void ChannelManager::RegisterChannel(const std::string &service_name,
    Channel* channel) {
  channels_[service_name] = channel;
}

int ChannelManager::StartTransport(boost::uint16_t port,
    boost::function<void(const bool&, const std::string&,
                         const boost::uint16_t&)> notify_dead_server) {
  base::pd_scoped_lock guard(*pmutex_);
  if (is_started)
    return 0;
  int start_res_(-1);
  // if no port assigned, get a random port between 1025 & 65536 inclusive
  if (0 == port)
    port = static_cast<boost::uint16_t>
        (base::random_32bit_uinteger() % (kMaxPort - kMinPort + 1)) + kMinPort;
  current_request_id_ =
      base::generate_next_transaction_id(current_request_id_)+(port*100);
  // iterate once through ports 1025 to 65536 until success, starting at random
  // port above
  boost::uint16_t count_(0);
  boost::uint16_t try_port_ = port;
  while (count_ <= (kMaxPort - kMinPort + 1)) {
    if (0 == ptransport_->Start(try_port_,
                                boost::bind(&ChannelManager::MessageArrive,
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

int ChannelManager::StopTransport() {
  if (!is_started) {
    return 0;
  }
  is_started = false;
  ptransport_->Stop();
  routingtable_->Clear();
  return 1;
}

void ChannelManager::MessageArrive(const std::string &message,
    const boost::uint32_t &connection_id) {
  // base::pd_scoped_lock guard(*pmutex_);
  // decode the message
  RpcMessage decoded_msg;
  if (!decoded_msg.ParseFromString(message)) {  // ignore invalid message
    // TRI_LOG_STR("Invalid message received. ");
    printf("Invalid message received\n");
    return;
  }
  // handle the message
  if (decoded_msg.rpc_type() == REQUEST) {
    if (!decoded_msg.has_service() || !decoded_msg.has_method()) {
      return;
    }
    // If this is a special find node for boostrapping,
    // inject incoming address
    if (decoded_msg.method() == "Bootstrap") {
      // right? what's name for find node rpc?
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
    it = channels_.find(decoded_msg.service());
    if (it != channels_.end()) {
      channels_[decoded_msg.service()]->HandleRequest(decoded_msg,
        connection_id);
    } else {
      printf("service not registered\n");
    }
//    printf("finished request -- %d\n", connection_id);
  } else if (decoded_msg.rpc_type() == RESPONSE) {
    // printf(" %s response arrived id %d \n", decoded_msg.method().c_str(),
    //     decoded_msg.message_id());
    std::map<boost::uint32_t, PendingReq>::iterator it;
    it = pending_req_.find(decoded_msg.message_id());
    if (it != pending_req_.end()) {
      google::protobuf::Message* response =
          pending_req_[decoded_msg.message_id()].args;
      if (response->ParseFromString(decoded_msg.args())) {
        google::protobuf::Closure* done =
            pending_req_[decoded_msg.message_id()].callback;
        DeleteRequest(decoded_msg.message_id());
        done->Run();
        // DeleteRequest(decoded_msg.message_id());
        ptransport_->CloseConnection(connection_id);
      }
    }
  } else {
  #ifdef DEBUG
    printf("Unknown type of message received. \n");
  #endif
    // TRI_LOG_STR("Unknown type of message received. ");
  }
}

void ChannelManager::TimerHandler(const boost::uint32_t &req_id) {
  // First of all, check whether the callback function is called or not, if it
  // has already been called, ignore this RPC timeout. I

  // TODO(dirvine/Haiyang): define a more reasonable time for a timeout or
  // right now it is 7 seconds for all rpc's.  In case the time for a timeout
  // is different for each rpc, then we should stored in the map or in a struct
  // to check the type of rpc to check the corresponding timeout
  // Or confirm that this is enough
  if (!is_started) return;
  std::map<boost::uint32_t, PendingReq>::iterator it;
  it = pending_req_.find(req_id);
  if (it != pending_req_.end()) {
#ifdef DEBUG
     printf("transport %d Request times out. RPC ID: %d\n",
         ptransport_->listening_port(), req_id);
#endif
    // TRI_LOG_STR("Request times out. RPC ID: "<< req_id);
    // call back without modifying the response
    google::protobuf::Closure* done = pending_req_[req_id].callback;
    if (pending_req_[req_id].connection_id != 0) {
      ptransport_->CloseConnection(pending_req_[req_id].connection_id);
    }
    done->Run();
    pending_req_.erase(req_id);
  }
}

void ChannelManager::UnRegisterChannel(const std::string &service_name) {
  base::pd_scoped_lock gaurd(*pmutex_);
  channels_.erase(service_name);
}

transport::Transport* ChannelManager::ptransport() {
  return ptransport_;
}

void ChannelManager::ClearChannels() {
  base::pd_scoped_lock gaurd(*pmutex_);
  channels_.clear();
}

void ChannelManager::AddConnectionToReq(const boost::uint32_t &req_id,
      const boost::uint32_t &conn_id) {
  std::map<boost::uint32_t, PendingReq>::iterator it;
  it = pending_req_.find(req_id);
  if (it != pending_req_.end()) {
    pending_req_[req_id].connection_id = conn_id;
  }
}
bool ChannelManager::CheckConnection(const std::string &ip,
    const uint16_t &port) {
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
