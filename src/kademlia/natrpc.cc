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

#include "kademlia/natrpc.h"
#include "maidsafe/channel.h"

namespace kad {

NatRpcs::NatRpcs(boost::shared_ptr<rpcprotocol::ChannelManager> ch_manager)
    : pchannel_manager_(ch_manager) {}

void NatRpcs::NatDetection(const std::string &newcomer,
      const std::string &bootstrap_node, const boost::uint32_t type,
      const std::string &sender_id, const std::string &remote_ip,
      const boost::uint16_t &remote_port, const std::string &rv_ip,
      const boost::uint16_t &rv_port, NatDetectionResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *cb) {
  NatDetectionRequest args;
  args.set_newcomer(newcomer);
  args.set_bootstrap_node(bootstrap_node);
  args.set_type(type);
  args.set_sender_id(sender_id);
  rpcprotocol::Channel channel(pchannel_manager_.get(), remote_ip, remote_port,
      "", 0, rv_ip, rv_port);
  if (type == 2)
    ctler->set_timeout(18);
  KademliaService::Stub service(&channel);
  service.NatDetection(ctler, &args, resp, cb);
}

void NatRpcs::NatDetectionPing(const std::string &remote_ip,
    const boost::uint16_t &remote_port, const std::string &rv_ip,
    const boost::uint16_t &rv_port, NatDetectionPingResponse *resp,
    rpcprotocol::Controller *ctler, google::protobuf::Closure *cb) {
  NatDetectionPingRequest args;
  args.set_ping("nat_detection_ping");
  rpcprotocol::Controller controller;
  controller.set_timeout(kRpcNatPingTimeout);
  rpcprotocol::Channel channel(pchannel_manager_.get(), remote_ip, remote_port,
      "", 0, rv_ip, rv_port);
  KademliaService::Stub service(&channel);
  service.NatDetectionPing(ctler, &args, resp, cb);
}
}
