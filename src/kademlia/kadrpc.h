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
#ifndef KADEMLIA_KADRPC_H_
#define KADEMLIA_KADRPC_H_

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include "protobuf/kademlia_service.pb.h"

namespace rpcprotocol {
class ChannelManager;
}

namespace kad {
// different RPCs have different timeouts, normally it is 5 seconds
const int kRpcPingTimeout = 3;  // 3 secs
const int kRpcBootstrapTimeout = 7;  // 7secs
class KadRpcs {
 public:
  explicit KadRpcs(boost::shared_ptr<rpcprotocol::ChannelManager>
      channel_manager);
  void FindNode(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, FindResponse *resp,
      google::protobuf::Closure *cb, const bool &local);
  void FindValue(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, FindResponse *resp,
      google::protobuf::Closure *cb, const bool &local);
  void Ping(const std::string &ip, const boost::uint16_t &port,
      PingResponse *resp, google::protobuf::Closure *cb, const bool &local);
  void Store(const std::string &key, const std::string &value,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &signed_request, const std::string &ip,
      const boost::uint16_t &port, StoreResponse *resp,
      google::protobuf::Closure *cb, const bool &local);
  void Downlist(const std::vector<std::string> downlist,
      const std::string &ip, const boost::uint16_t &port,
      DownlistResponse *resp, google::protobuf::Closure *cb, const bool &local);
  void NatDetection(const std::string &newcomer,
      const std::string &bootstrap_node,
      const boost::uint32_t type,
      const std::string &sender_id,
      const std::string &remote_ip,
      const boost::uint16_t &remote_port,
      NatDetectionResponse *resp,
      google::protobuf::Closure *cb);
  void NatDetectionPing(const std::string &remote_ip,
      const boost::uint16_t &remote_port,
      NatDetectionPingResponse *resp,
      google::protobuf::Closure *cb);
  void Bootstrap(const std::string &local_id,
      const std::string &local_ip,
      const boost::uint16_t &local_port,
      const std::string &remote_ip,
      const boost::uint16_t &remote_port,
      BootstrapResponse *resp,
      google::protobuf::Closure *cb);
  void set_info(const ContactInfo &info);
 private:
  KadRpcs(const KadRpcs&);
  KadRpcs& operator=(const KadRpcs&);
  ContactInfo info_;
  boost::shared_ptr<rpcprotocol::ChannelManager> pchannel_manager_;
};
}  // namespace kad

#endif  // KADEMLIA_KADRPC_H_
