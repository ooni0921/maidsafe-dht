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

#ifndef KADEMLIA_KADSERVICE_H_
#define KADEMLIA_KADSERVICE_H_
#include <memory>
#include <string>
#include <vector>
#include "base/routingtable.h"
#include "gtest/gtest_prod.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "protobuf/kademlia_service.pb.h"

namespace kad {
class KNodeImpl;

struct NatDetectionData {
  // std::string sender_id;
  Contact newcomer;
  std::string bootstrap_node;
  Contact node_c;
  BootstrapResponse *response;
  google::protobuf::Closure *done;
  rpcprotocol::Controller *controller;
  std::vector<Contact> ex_contacts;
};

struct NatDetectionPingData {
  std::string sender_id;
  NatDetectionResponse *response;
  google::protobuf::Closure *done;
  rpcprotocol::Controller *controller;
};

class KadService : public KademliaService {
 public:
  explicit KadService(KNodeImpl *knode);
  virtual void Ping(google::protobuf::RpcController *controller,
      const PingRequest *request, PingResponse *response,
      google::protobuf::Closure *done);
  virtual void FindValue(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done);
  virtual void FindNode(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done);
  virtual void Store(google::protobuf::RpcController *controller,
      const StoreRequest *request, StoreResponse *response,
      google::protobuf::Closure *done);
  virtual void Downlist(google::protobuf::RpcController *controller,
      const DownlistRequest *request, DownlistResponse *response,
      google::protobuf::Closure *done);
  virtual void NatDetection(google::protobuf::RpcController *controller,
      const NatDetectionRequest *request, NatDetectionResponse *response,
      google::protobuf::Closure *done);
  virtual void NatDetectionPing(google::protobuf::RpcController *controller,
      const NatDetectionPingRequest *request,
      NatDetectionPingResponse *response,
      google::protobuf::Closure *done);
  virtual void Bootstrap(google::protobuf::RpcController *controller,
      const BootstrapRequest *request, BootstrapResponse *response,
      google::protobuf::Closure *done);
  friend class NatDetectionTest;
 private:
  FRIEND_TEST(KadServicesTest, BEH_KAD_ServicesValidateSignedRequest);
  FRIEND_TEST(NatDetectionTest, BEH_KAD_SendNatDet);
  FRIEND_TEST(NatDetectionTest, BEH_KAD_BootstrapNatDetRv);
  FRIEND_TEST(NatDetectionTest, FUNC_KAD_CompleteBootstrapNatDet);
  bool ValidateSignedRequest(const std::string &public_key, const std::string
      &signed_public_key, const std::string &signed_request, const std::string
      &key);
  bool GetSender(const ContactInfo &sender_info, Contact *sender);
  void RpcDownlist_Remove(const std::string &ser_response, Contact dead_node);
  void Bootstrap_NatDetectionRv(const NatDetectionResponse *response,
      struct NatDetectionData data);
  void Bootstrap_NatDetection(const NatDetectionResponse *response,
      struct NatDetectionData data);
  void Bootstrap_NatDetectionPing(const NatDetectionPingResponse *response,
      struct NatDetectionPingData data);
  void Bootstrap_NatDetectionRzPing(
      const NatDetectionPingResponse *response,
      struct NatDetectionPingData data);
  void SendNatDetection(struct NatDetectionData data);
  bool CheckStoreRequest(const StoreRequest *request, Contact *sender);
  void StoreValueLocal(const std::string &key,
      const std::string &value, Contact sender, const boost::uint32_t &ttl,
      const bool &publish, StoreResponse *response,
      rpcprotocol::Controller *ctrl);
  void StoreValueLocal(const std::string &key,
      const SignedValue &value, Contact sender, const boost::uint32_t &ttl,
      const bool &publish, StoreResponse *response,
      rpcprotocol::Controller *ctrl);
  KNodeImpl *knode_;
  // boost::shared_ptr<base::PDRoutingTableHandler> routingtable_;
  KadService(const KadService&);
  KadService& operator=(const KadService&);
};
}  // namespace
#endif  // KADEMLIA_KADSERVICE_H_
