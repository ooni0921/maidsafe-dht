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
#include "gtest/gtest_prod.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "protobuf/kademlia_service.pb.h"
#include "kademlia/natrpc.h"

namespace base {
class SignatureValidator;
}

namespace kad {
class DataStore;
class Contact;
class KadId;

typedef boost::function< int(Contact, const float&, const bool&) >  // NOLINT
    add_contact_function;
typedef boost::function< void(const boost::uint16_t&, const
    std::vector<Contact>&, std::vector<Contact>*) >
    get_random_contacts_function;
typedef boost::function< bool(const  KadId&, Contact*) >  // NOLINT
    get_contact_function;
typedef boost::function< void(const KadId&, std::vector<Contact>*,
    const std::vector<Contact>&) > get_closestK_function;
typedef boost::function< void(const Contact&, base::callback_func_type) >
    ping_function;

struct NatDetectionData {
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
  KadService(const NatRpcs &nat_rpcs, boost::shared_ptr<DataStore> datastore,
      const bool &hasRSAkeys, add_contact_function add_cts,
      get_random_contacts_function rand_cts, get_contact_function get_ctc,
      get_closestK_function get_kcts, ping_function ping);
  void Ping(google::protobuf::RpcController *controller,
      const PingRequest *request, PingResponse *response,
      google::protobuf::Closure *done);
  void FindValue(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done);
  void FindNode(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done);
  void Store(google::protobuf::RpcController *controller,
      const StoreRequest *request, StoreResponse *response,
      google::protobuf::Closure *done);
  void Downlist(google::protobuf::RpcController *controller,
      const DownlistRequest *request, DownlistResponse *response,
      google::protobuf::Closure *done);
  void NatDetection(google::protobuf::RpcController *controller,
      const NatDetectionRequest *request, NatDetectionResponse *response,
      google::protobuf::Closure *done);
  void NatDetectionPing(google::protobuf::RpcController *controller,
      const NatDetectionPingRequest *request,
      NatDetectionPingResponse *response,
      google::protobuf::Closure *done);
  void Bootstrap(google::protobuf::RpcController *controller,
      const BootstrapRequest *request, BootstrapResponse *response,
      google::protobuf::Closure *done);
  void Delete(google::protobuf::RpcController *controller,
      const DeleteRequest *request, DeleteResponse *response,
      google::protobuf::Closure *done);
  inline void set_node_joined(const bool &joined) {
    node_joined_ = joined;
  }
  inline void set_node_info(const ContactInfo &info) {
    node_info_ = info;
  }
  inline void set_alternative_store(base::AlternativeStore* alt_store) {
    alternative_store_ = alt_store;
  }
  inline void set_signature_validator(base::SignatureValidator *sig_validator) {
    signature_validator_ = sig_validator;
  }
 private:
  FRIEND_TEST(NatDetectionTest, BEH_KAD_SendNatDet);
  FRIEND_TEST(NatDetectionTest, BEH_KAD_BootstrapNatDetRv);
  FRIEND_TEST(NatDetectionTest, FUNC_KAD_CompleteBootstrapNatDet);
//  bool ValidateSignedRequest(const std::string &public_key, const std::string
//      &signed_public_key, const std::string &signed_request, const std::string
//      &key);
  bool GetSender(const ContactInfo &sender_info, Contact *sender);
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
      const std::string &value, Contact sender, const boost::int32_t &ttl,
      const bool &publish, StoreResponse *response,
      rpcprotocol::Controller *ctrl);
  void StoreValueLocal(const std::string &key,
      const SignedValue &value, Contact sender, const boost::int32_t &ttl,
      const bool &publish, StoreResponse *response,
      rpcprotocol::Controller *ctrl);
  bool CanStoreSignedValueHashable(const std::string &key,
      const std::string &value, bool *hashable);
  NatRpcs nat_rpcs_;
  boost::shared_ptr<DataStore> pdatastore_;
  bool node_joined_, node_hasRSAkeys_;
  ContactInfo node_info_;
  base::AlternativeStore *alternative_store_;
  add_contact_function add_contact_;
  get_random_contacts_function get_random_contacts_;
  get_contact_function get_contact_;
  get_closestK_function get_closestK_contacts_;
  ping_function ping_;
  base::SignatureValidator *signature_validator_;
  KadService(const KadService&);
  KadService& operator=(const KadService&);
};
}  // namespace
#endif  // KADEMLIA_KADSERVICE_H_
