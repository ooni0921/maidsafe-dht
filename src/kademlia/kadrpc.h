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

#ifndef KADEMLIA_KADRPC_H_
#define KADEMLIA_KADRPC_H_

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include "maidsafe/channelmanager-api.h"
#include "protobuf/kademlia_service.pb.h"
#include "maidsafe/transporthandler-api.h"

namespace kad {
// different RPCs have different timeouts, normally it is 5 seconds
const boost::uint32_t kRpcPingTimeout = 3;  // 3 secs
const boost::uint32_t kRpcBootstrapTimeout = 7;  // 7secs
class KadRpcs {
 public:
  KadRpcs(rpcprotocol::ChannelManager *channel_manager,
      transport::TransportHandler *ptrans_handler);
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
      const SignedRequest &sig_req, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, StoreResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb,
      const boost::int32_t &ttl, const bool &publish);
  void Store(const std::string &key, const std::string &value,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      StoreResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb, const boost::int32_t &ttl,
      const bool &publish);
  void Downlist(const std::vector<std::string> downlist,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port,
      DownlistResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb);
  void Bootstrap(const std::string &local_id, const std::string &local_ip,
      const boost::uint16_t &local_port, const std::string &remote_ip,
      const boost::uint16_t &remote_port, const node_type &type,
      BootstrapResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *cb);
  void Delete(const std::string &key, const SignedValue &value,
      const SignedRequest &sig_req, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, DeleteResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb);
  void set_info(const ContactInfo &info);
 private:
  KadRpcs(const KadRpcs&);
  KadRpcs& operator=(const KadRpcs&);
  ContactInfo info_;
  rpcprotocol::ChannelManager *pchannel_manager_;
  transport::TransportHandler *ptrans_handler_;
};
}  // namespace kad

#endif  // KADEMLIA_KADRPC_H_
