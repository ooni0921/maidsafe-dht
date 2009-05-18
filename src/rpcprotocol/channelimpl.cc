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

#include <boost/tokenizer.hpp>
#include <google/protobuf/descriptor.h>
#include <typeinfo>
#include "maidsafe/maidsafe-dht.h"
#include "protobuf/rpcmessage.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "rpcprotocol/channelimpl.h"
#include "rpcprotocol/channelmanagerimpl.h"

namespace rpcprotocol {

struct RpcInfo {
  RpcInfo() : ctrl(0), rpc_id(0), connection_id(0) {}
  ControllerImpl *ctrl;
  boost::uint32_t rpc_id;
  boost::uint32_t connection_id;
};

ChannelImpl::ChannelImpl(
    boost::shared_ptr<rpcprotocol::ChannelManager> channelmanager)
        : pmanager_(channelmanager),
          ptransport_(pmanager_->ptransport()),
          pservice_(0),
          ip_(""),
          port_(0),
          routingtable_(new base::PDRoutingTableHandler(base::itos(
              pmanager_->external_port()))),
          local_(false),
          mutex() {}

ChannelImpl::ChannelImpl(
    boost::shared_ptr<rpcprotocol::ChannelManager> channelmanager,
    const std::string &ip,
    const boost::uint16_t &port,
    const bool &local)
        : pmanager_(channelmanager),
          ptransport_(pmanager_->ptransport()),
          pservice_(0),
          ip_(""),
          port_(port),
          routingtable_(new base::PDRoutingTableHandler(base::itos(
              pmanager_->external_port()))),
          local_(local),
          mutex() {
  // To send we need ip in decimal dotted format
  if (ip.size() == 4)
    ip_ = base::inet_btoa(ip);
  else
    ip_ = ip;
}

ChannelImpl::~ChannelImpl() {}

void ChannelImpl::CallMethod(const google::protobuf::MethodDescriptor *method,
                             google::protobuf::RpcController *controller,
                             const google::protobuf::Message *request,
                             google::protobuf::Message *response,
                             google::protobuf::Closure *done) {
  if ((ip_ == "") || (port_ == 0)) {
#ifdef DEBUG
    printf("No remote_ip or no remote_port.\n");
#endif
    done->Run();
    return;
  }
  RpcMessage msg;
  msg.set_message_id(pmanager_->CreateNewId());
  msg.set_rpc_type(REQUEST);
  std::string ser_args;
  request->SerializeToString(&ser_args);
  msg.set_args(ser_args);
  msg.set_service(GetServiceName(method->full_name()));
  msg.set_method(method->name());

  PendingReq req;
  req.args = response;
  req.callback = done;
  boost::uint32_t conn_id;
  boost::uint32_t req_id = msg.message_id();
#ifdef VERBOSE_DEBUG
  printf("In Channel::CallMethod, adding pending request %i.\n", req_id);
#endif
  pmanager_->AddPendingRequest(msg.message_id(), req);
  std::string ser_msg;
  msg.SerializeToString(&ser_msg);
#ifdef VERBOSE_DEBUG
    printf("Sending %s request %d to %s:%d\n", msg.method().c_str(),
      msg.message_id(), ip_.c_str(), port_);
#endif
  std::string rendezvous_ip("");
  uint16_t rendezvous_port = 0;
  base::PDRoutingTableTuple tuple;
  if (!local_)
    if (0 == routingtable_->GetTupleInfo(ip_, port_, &tuple)) {
      rendezvous_ip = tuple.rendezvous_ip();
      rendezvous_port = tuple.rendezvous_port();
//      if (rendezvous_ip != "" && rendezvous_port !=0)
//        printf("node has rendezvous information\n");
    }
  // Set the RPC request timeout
  ControllerImpl *ctrl = static_cast<ControllerImpl*>(controller);
  if (0 != ptransport_->Send(ip_,
                        port_,
                        rendezvous_ip,
                        rendezvous_port,
                        ser_msg,
                        transport::Transport::STRING,
                        &conn_id,
                        true)) {
#ifdef VERBOSE_DEBUG
    printf("Failed to send request %i.\n", req_id);
#endif
    // Set short timeout as request has already failed.
    ctrl->set_timeout(1);
  }
  pmanager_->AddConnectionToReq(req_id, conn_id);
  // in case no timeout was set in the controller use the default one
  if (ctrl->timeout() != 0) {
    pmanager_->AddReqToTimer(msg.message_id(), ctrl->timeout());
  } else {
    pmanager_->AddReqToTimer(msg.message_id(), kRpcTimeout);
  }
}

std::string ChannelImpl::GetServiceName(const std::string &full_name) {
  std::string service_name;
  try {
    boost::char_separator<char> sep(".");
    boost::tokenizer<boost::char_separator<char> > tok(full_name, sep);
    boost::tokenizer<boost::char_separator<char> >::iterator beg = tok.begin();
    int no_tokens = -1;
    while (beg != tok.end()) {
      ++beg;
      ++no_tokens;
    }
    beg = tok.begin();
    advance(beg, no_tokens - 1);
    service_name = *beg;
  } catch(const std::exception &e) {
#ifdef DEBUG
    printf("Error with full method name format: %s.\n", e.what());
#endif
  }
  return service_name;
}

void ChannelImpl::SetService(google::protobuf::Service* service) {
  pservice_ = service;
}

void ChannelImpl::HandleRequest(const RpcMessage &request,
                                const boost::uint32_t &connection_id) {
#ifdef SHOW_MUTEX
  printf("In Channel::HandleRequest (connection %i), outside mutex.\n",
         connection_id);
#endif
  boost::mutex::scoped_lock guard(mutex);
#ifdef SHOW_MUTEX
  printf("In Channel::HandleRequest (connection %i), inside mutex.\n",
         connection_id);
#endif
  if (pservice_) {
#ifdef VERBOSE_DEBUG
    printf("In Channel::HandleRequest (connection %i), method", connection_id);
    printf(" = %s.\n", request.method().c_str());
#endif
    const google::protobuf::MethodDescriptor* method =
        pservice_->GetDescriptor()->FindMethodByName(request.method());
    google::protobuf::Message* args  =
        pservice_->GetRequestPrototype(method).New();
    google::protobuf::Message* response  =
        pservice_->GetResponsePrototype(method).New();
    if (!args->ParseFromString(request.args())) {
#ifdef VERBOSE_DEBUG
      printf("In Channel::HandleRequest, failed to parse request - closing");
      printf(" connection %i.\n", connection_id);
#endif
      ptransport_->CloseConnection(connection_id);
      delete args;
#ifdef SHOW_MUTEX
      printf("In Channel::HandleRequest (connection %i), unlock 1.\n",
             connection_id);
#endif
      return;
    }
    ControllerImpl *controller = new ControllerImpl;
    RpcInfo info;
    info.ctrl = controller;
    info.rpc_id = request.message_id();
    info.connection_id = connection_id;
    google::protobuf::Closure *done = google::protobuf::NewCallback<ChannelImpl,
        const google::protobuf::Message*, RpcInfo> (this,
        &ChannelImpl::SendResponse, response, info);
    pservice_->CallMethod(method, controller, args, response, done);
    delete args;
#ifdef SHOW_MUTEX
    printf("In Channel::HandleRequest (connection %i), unlock 2.\n",
           connection_id);
#endif
    return;
  }
  ptransport_->CloseConnection(connection_id);
#ifdef SHOW_MUTEX
  printf("In Channel::HandleRequest (connection %i), unlock 3.\n",
         connection_id);
#endif
}

void ChannelImpl::SendResponse(const google::protobuf::Message *response,
                               RpcInfo info) {
  RpcMessage response_msg;
  response_msg.set_message_id(info.rpc_id);
  response_msg.set_rpc_type(RESPONSE);
  std::string ser_response;
  response->SerializeToString(&ser_response);
  // TODO(dirvine): Confirm we need to serialise to string I think we dont
  // and it would be more efficient not to !
  response_msg.set_args(ser_response);
  std::string ser_msg;
  response_msg.SerializeToString(&ser_msg);
// #ifdef DEBUG
//  printf("sending response to %s:%d\n", info.ctrl->remote_ip().c_str(),
//      info.ctrl->remote_port());
// #endif
//  if (0 != ptransport_->Send(info.ctrl->remote_ip(), info.ctrl->remote_port(),
//      ser_msg, transport::Transport::STRING)) {
//  printf("transport: %d - sending the response to req %d\n",
//    ptransport_->listening_port(), info.connection_id);
  if (0 != ptransport_->Send(info.connection_id, ser_msg,
                             transport::Transport::STRING)) {
#ifdef DEBUG
    printf("Failed to send response to connection %d.\n", info.connection_id);
#endif

// #ifdef DEBUG
//  printf("failed to send response to %s:%d\n", info.ctrl->remote_ip().c_str(),
//        info.ctrl->remote_port());
// #endif
  }
  // printf("response to req %d sent\n", info.rpc_id);
  delete response;
  delete info.ctrl;
}
}  // namespace rpcprotocol
