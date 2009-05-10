/*
Copyright (c) 2009 maidsafe.net limited
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
