

#ifndef KADEMLIA_KADRPC_H_
#define KADEMLIA_KADRPC_H_

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include "maidsafe/channelmanager-api.h"
#include "protobuf/kademlia_service.pb.h"

namespace kad {
// different RPCs have different timeouts, normally it is 5 seconds
const int kRpcPingTimeout = 3;  // 3 secs
const int kRpcBootstrapTimeout = 7;  // 7secs
class KadRpcs {
 public:
  KadRpcs(rpcprotocol::ChannelManager *channel_manager,
      transport::Transport *trans);
  void FindNode(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, FindResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb);
  void FindValue(const std::string &key, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, FindResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb);
  void Ping(const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      PingResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb);
  void Store(const std::string &key, const SignedValue &value,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &signed_request, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, StoreResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb,
      const boost::uint32_t &ttl, const bool &publish);
  void Store(const std::string &key, const std::string &value,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      StoreResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb, const boost::uint32_t &ttl,
      const bool &publish);
  void Downlist(const std::vector<std::string> downlist,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      DownlistResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb);
  void Bootstrap(const std::string &local_id, const std::string &local_ip,
      const boost::uint16_t &local_port, const std::string &remote_ip,
      const boost::uint16_t &remote_port, BootstrapResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb);
  void set_info(const ContactInfo &info);
 private:
  KadRpcs(const KadRpcs&);
  KadRpcs& operator=(const KadRpcs&);
  ContactInfo info_;
  rpcprotocol::ChannelManager *pchannel_manager_;
  transport::Transport *ptransport_;
};
}  // namespace kad

#endif  // KADEMLIA_KADRPC_H_
