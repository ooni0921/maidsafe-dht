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
#include "maidsafe/channel-api.h"

namespace kad {

KadRpcs::KadRpcs(rpcprotocol::ChannelManager *channel_manager,
    transport::Transport *trans) : info_(), pchannel_manager_(channel_manager),
    ptransport_(trans) {
}

void KadRpcs::set_info(const ContactInfo &info) {
  info_ = info;
}

void KadRpcs::FindNode(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, FindResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb) {
  FindRequest args;
  if (resp->has_requester_ext_addr()) {
    // This is a special find node RPC for bootstrapping process
    args.set_is_boostrap(true);  // Set flag
    ctler->set_timeout(kRpcBootstrapTimeout);  // Longer timeout
  }
  args.set_key(key);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, ip, port, "", 0,
      rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.FindNode(ctler, &args, resp, cb);
}

void KadRpcs::FindValue(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, FindResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb) {
  FindRequest args;
  args.set_key(key);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, ip, port, "", 0,
      rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.FindValue(ctler, &args, resp, cb);
}

void KadRpcs::Ping(const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      PingResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb) {
  PingRequest args;
  args.set_ping("ping");
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  ctler->set_timeout(kRpcPingTimeout);
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, ip, port, "", 0,
      rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.Ping(ctler, &args, resp, cb);
}

void KadRpcs::Store(const std::string &key, const SignedValue &value,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &signed_request, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, StoreResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb,
      const boost::uint32_t &ttl, const bool &publish) {
  StoreRequest args;
  args.set_key(key);
  SignedValue *svalue = args.mutable_sig_value();
  *svalue = value;
  args.set_ttl(ttl);
  args.set_publish(publish);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, ip, port, "", 0,
      rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.Store(ctler, &args, resp, cb);
}

void KadRpcs::Store(const std::string &key, const std::string &value,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      StoreResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb, const boost::uint32_t &ttl,
      const bool &publish) {
  StoreRequest args;
  args.set_key(key);
  args.set_value(value);
  args.set_ttl(ttl);
  args.set_publish(publish);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, ip, port, "", 0,
      rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.Store(ctler, &args, resp, cb);
}

void KadRpcs::Downlist(const std::vector<std::string> downlist,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      DownlistResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb) {
  DownlistRequest args;
  for (unsigned int i = 0; i < downlist.size(); i++)
    args.add_downlist(downlist[i]);
  rpcprotocol::Controller controller;
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, ip, port, "", 0,
      rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.Downlist(ctler, &args, resp, cb);
}

void KadRpcs::Bootstrap(const std::string &local_id,
    const std::string &local_ip, const boost::uint16_t &local_port,
    const std::string &remote_ip, const boost::uint16_t &remote_port,
    BootstrapResponse *resp, rpcprotocol::Controller *ctler,
    google::protobuf::Closure *cb) {
  BootstrapRequest args;
  args.set_newcomer_id(local_id);
  args.set_newcomer_local_ip(local_ip);
  args.set_newcomer_local_port(local_port);
  ctler->set_timeout(20);
  rpcprotocol::Channel channel(pchannel_manager_, ptransport_, remote_ip,
      remote_port, "", 0, "", 0);
  KademliaService::Stub service(&channel);
  service.Bootstrap(ctler, &args, resp, cb);
}
}  // namepsace
