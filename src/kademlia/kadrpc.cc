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

#include "kademlia/kadrpc.h"
#include "rpcprotocol/channelmanager.h"
#include "rpcprotocol/channel.h"

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
  rpcprotocol::Controller controller;
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
      pchannel_manager_->ptransport(), pchannel_manager_.get(), ip,
      port, local));
  KademliaService::Stub service(channel.get());
  service.FindNode(&controller, &args, resp, cb);
}

void KadRpcs::FindValue(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, FindResponse *resp,
      google::protobuf::Closure *cb, const bool &local) {
  FindRequest args;
  rpcprotocol::Controller controller;
  args.set_key(key);
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), ip,
      port, local));
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
  rpcprotocol::Controller controller;
  controller.set_timeout(kRpcPingTimeout);
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), ip,
      port, local));
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
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), ip,
      port, local));
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
  rpcprotocol::Controller controller;
  ContactInfo *sender_info = args.mutable_sender_info();
  *sender_info = info_;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), ip,
      port, local));
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
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), remote_ip,
      remote_port, false));
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
  rpcprotocol::Controller controller;
  controller.set_timeout(kRpcPingTimeout);
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), remote_ip,
      remote_port, false));
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
  rpcprotocol::Controller controller;
  controller.set_timeout(20);
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      pchannel_manager_->ptransport(), pchannel_manager_.get(), remote_ip,
      remote_port, false));
  KademliaService::Stub service(channel.get());
  service.Bootstrap(&controller, &args, resp, cb);
}
}  // namepsace
