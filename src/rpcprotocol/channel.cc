/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Feb 12, 2009
 *      Author: Jose
 */

#include "rpcprotocol/channel.h"
#include <boost/tokenizer.hpp>
#include <google/protobuf/descriptor.h>
#include <typeinfo>
#include "rpcprotocol/channelmanager.h"
#include "base/tri_logger.h"
#include "protobuf/rpcmessage.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"

namespace rpcprotocol {

Channel::Channel(boost::shared_ptr<transport::Transport> transport,
      ChannelManager *channelmanager)
    : ptransport_(transport),
      pmanager_(channelmanager),
      pservice_(0),
      ip_(""),
      port_(0),
      routingtable_(new base::PDRoutingTableHandler(
        base::itos(pmanager_->external_port()))),
      local_(false),
      mutex() {
}

Channel::Channel(boost::shared_ptr<transport::Transport> transport,
      ChannelManager *channelmanager, const std::string &ip,
      const boost::uint16_t &port, const bool &local)
    : ptransport_(transport),
      pmanager_(channelmanager),
      pservice_(0),
      ip_(""),
      port_(port),
      routingtable_(new base::PDRoutingTableHandler(
        base::itos(pmanager_->external_port()))),
      local_(local),
      mutex() {
  // To send we need ip in decimal dotted format
  if (ip.size() == 4)
    ip_ = base::inet_btoa(ip);
  else
    ip_ = ip;
}

Channel::~Channel() {}

void Channel::CallMethod(const google::protobuf::MethodDescriptor *method,
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
  Controller *ctrl = static_cast<Controller*>(controller);
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

std::string Channel::GetServiceName(const std::string &full_name) {
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

void Channel::HandleRequest(const RpcMessage &request,
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
    Controller *controller = new Controller;
    RpcInfo info;
    info.ctrl = controller;
    info.rpc_id = request.message_id();
    info.connection_id = connection_id;
    google::protobuf::Closure *done = google::protobuf::NewCallback<Channel,
        const google::protobuf::Message*, RpcInfo> (this,
        &Channel::SendResponse, response, info);
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

void Channel::SendResponse(const google::protobuf::Message *response,
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
