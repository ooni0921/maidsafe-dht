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

#include "kademlia/kadrpc.h"
#include "maidsafe/maidsafe-dht.h"
#include "rpcprotocol/channelimpl.h"

namespace kad {

KadRpcs::KadRpcs(boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager)
    : info_(), pchannel_manager_(channel_manager) {
}

void KadRpcs::set_info(const ContactInfo &info) {
  info_ = info;
}

void KadRpcs::FindNode(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, FindResponse *resp,
      google::protobuf::Closure *cb, const bool &local) {
  rpcprotocol::ControllerImpl controller;
  FindRequest args;
  if (resp->has_requester_ext_addr()) {
    // This is a special find node RPC for bootstrapping process
    args.set_is_boostrap(true);  // Set flag
    controller.set_timeout(kRpcBootstrapTimeout);  // Longer timeout
  }
  args.set_key(key);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, ip, port, local));
  KademliaService::Stub service(channel.get());
  service.FindNode(&controller, &args, resp, cb);
}

void KadRpcs::FindValue(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, FindResponse *resp,
      google::protobuf::Closure *cb, const bool &local) {
  FindRequest args;
  rpcprotocol::ControllerImpl controller;
  args.set_key(key);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, ip, port, local));
  KademliaService::Stub service(channel.get());
  service.FindValue(&controller, &args, resp, cb);
}

void KadRpcs::Ping(const std::string &ip,
      const boost::uint16_t &port, PingResponse *resp,
      google::protobuf::Closure *cb, const bool &local) {
  PingRequest args;
  args.set_ping("ping");
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::ControllerImpl controller;
  controller.set_timeout(kRpcPingTimeout);
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, ip, port, local));
  KademliaService::Stub service(channel.get());
  service.Ping(&controller, &args, resp, cb);
}

void KadRpcs::Store(const std::string &key, const std::string &value,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &signed_request, const std::string &ip,
      const boost::uint16_t &port, StoreResponse *resp,
      google::protobuf::Closure *cb, const bool &local) {
  StoreRequest args;
  args.set_key(key);
  args.set_value(value);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::ControllerImpl controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, ip, port, local));
  KademliaService::Stub service(channel.get());
    service.Store(&controller, &args, resp, cb);
}

void KadRpcs::Downlist(const std::vector<std::string> downlist,
      const std::string &ip, const boost::uint16_t &port,
      DownlistResponse *resp, google::protobuf::Closure *cb,
      const bool &local) {
  DownlistRequest args;
  for (unsigned int i = 0; i < downlist.size(); i++)
    args.add_downlist(downlist[i]);
  rpcprotocol::ControllerImpl controller;
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, ip, port, local));
  KademliaService::Stub service(channel.get());
  service.Downlist(&controller, &args, resp, cb);
}

void KadRpcs::NatDetection(const std::string &newcomer,
      const std::string &bootstrap_node,
      const boost::uint32_t type,
      const std::string &sender_id,
      const std::string &remote_ip,
      const boost::uint16_t &remote_port,
      NatDetectionResponse *resp,
      google::protobuf::Closure *cb) {
  NatDetectionRequest args;
  args.set_newcomer(newcomer);
  args.set_bootstrap_node(bootstrap_node);
  args.set_type(type);
  args.set_sender_id(sender_id);
  rpcprotocol::ControllerImpl controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, remote_ip, remote_port, false));
  if (type == 2)
    controller.set_timeout(18);
  KademliaService::Stub service(channel.get());
  service.NatDetection(&controller, &args, resp, cb);
}
void KadRpcs::NatDetectionPing(const std::string &remote_ip,
    const boost::uint16_t &remote_port,
    NatDetectionPingResponse *resp,
    google::protobuf::Closure *cb) {
  NatDetectionPingRequest args;
  args.set_ping("nat_detection_ping");
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::ControllerImpl controller;
  controller.set_timeout(kRpcPingTimeout);
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, remote_ip, remote_port, false));
  KademliaService::Stub service(channel.get());
  service.NatDetectionPing(&controller, &args, resp, cb);
}

void KadRpcs::Bootstrap(const std::string &local_id,
    const std::string &local_ip,
    const boost::uint16_t &local_port,
    const std::string &remote_ip,
    const boost::uint16_t &remote_port,
    BootstrapResponse *resp,
    google::protobuf::Closure *cb) {
  BootstrapRequest args;
  args.set_newcomer_id(local_id);
  args.set_newcomer_local_ip(local_ip);
  args.set_newcomer_local_port(local_port);
  rpcprotocol::ControllerImpl controller;
  controller.set_timeout(20);
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_, remote_ip, remote_port, false));
  KademliaService::Stub service(channel.get());
  service.Bootstrap(&controller, &args, resp, cb);
}
}  // namepsace
