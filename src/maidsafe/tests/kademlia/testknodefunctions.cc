/* Copyright (c) 2010 maidsafe.net limited
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

#include <gtest/gtest.h>
#include <boost/lexical_cast.hpp>

#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/knode-api.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"

namespace kad {

namespace test_knode_functions {

class TestAlternativeStore : public base::AlternativeStore {
 public:
  ~TestAlternativeStore() {}
  bool Has(const std::string&) { return false; }
};

class TestValidator : public base::SignatureValidator {
 public:
  ~TestValidator() {}
  bool ValidateSignerId(const std::string&, const std::string&,
                        const std::string&) { return true; }
  bool ValidateRequest(const std::string&, const std::string&,
                       const std::string&, const std::string&) { return true; }
};

static const boost::uint16_t K = 16;

class TestKnodeFunctions : public testing::Test {
 protected:
  static void SetUpTestCase() {
    test_dir_ = std::string("temp/TestKnodeFunctions") +
                boost::lexical_cast<std::string>(base::RandomUint32());

    udt_ = new transport::TransportUDT;
    handler_ = new transport::TransportHandler;
    handler_->Register(udt_, &transport_id_);
    manager_ = new rpcprotocol::ChannelManager(handler_);

    crypto::RsaKeyPair rkp;
    rkp.GenerateKeys(4096);
    node_.reset(new KNode(manager_, handler_, kad::VAULT, K, kad::kAlpha,
                          kad::kBeta, kad::kRefreshTime, rkp.private_key(),
                          rkp.public_key(), false, false));
    node_->set_transport_id(transport_id_);

    EXPECT_TRUE(manager_->RegisterNotifiersToTransport());
    EXPECT_TRUE(handler_->RegisterOnServerDown(
                    boost::bind(&kad::KNode::HandleDeadRendezvousServer,
                                node_.get(), _1)));

    EXPECT_EQ(0, handler_->Start(0, transport_id_));
    EXPECT_EQ(0, manager_->Start());

    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    node_->Join(test_dir_ + std::string(".kadconfig"), local_ip.to_string(),
                handler_->listening_port(transport_id_),
                boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(node_->is_joined());
  }
  static void TearDownTestCase() {
    node_->Leave();
    delete manager_;
    delete udt_;
    delete handler_;
  }

  static std::string test_dir_;
  static boost::int16_t transport_id_;
  static transport::TransportUDT *udt_;
  static transport::TransportHandler *handler_;
  static rpcprotocol::ChannelManager *manager_;
  static boost::shared_ptr<KNode> node_;
  static GeneralKadCallback cb_;
};

std::string TestKnodeFunctions::test_dir_;
boost::int16_t TestKnodeFunctions::transport_id_ = 0;
transport::TransportUDT *TestKnodeFunctions::udt_ = NULL;
transport::TransportHandler *TestKnodeFunctions::handler_ = NULL;
rpcprotocol::ChannelManager *TestKnodeFunctions::manager_ = NULL;
boost::shared_ptr<KNode> TestKnodeFunctions::node_;
GeneralKadCallback TestKnodeFunctions::cb_;

TEST_F(TestKnodeFunctions, BEH_KNODE_GetKNodesFromRoutingTable) {
  KadId key(KadId::kRandomId);
  std::vector<Contact> exclude_contacts, close_nodes;
  node_->GetKNodesFromRoutingTable(key, exclude_contacts, &close_nodes);
  ASSERT_TRUE(close_nodes.empty());
}

TEST_F(TestKnodeFunctions, BEH_KNODE_AddGetRemoveContact) {
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  KadId key(KadId::kRandomId);
  Contact c(key, local_ip.to_string(), 5000, local_ip.to_string(), 5000), o, n;
  ASSERT_EQ(0, node_->AddContact(c, 1.0f, false));
  ASSERT_TRUE(node_->GetContact(key, &o));
  ASSERT_TRUE(c.Equals(o));
  std::vector<Contact> contacts;
  node_->GetRandomContacts(2, std::vector<Contact>(), &contacts);
  ASSERT_EQ(size_t(1), contacts.size());
  ASSERT_TRUE(c.Equals(contacts.at(0)));
  node_->RemoveContact(key);
  ASSERT_FALSE(node_->GetContact(key, &n));
  ASSERT_FALSE(c.Equals(n));
}

TEST_F(TestKnodeFunctions, BEH_KNODE_StoreRefreshTTLValueLocal) {
  KadId key(KadId::kRandomId);
  std::string value(base::RandomString(200));
  boost::uint32_t ttl(3600);
  node_->StoreValueLocal(key, value, ttl);
  ASSERT_EQ(ttl, node_->KeyValueTTL(key, value));
  boost::uint32_t rt = node_->KeyLastRefreshTime(key, value);
  boost::uint32_t et = node_->KeyExpireTime(key, value);
  node_->RefreshValueLocal(key, value, ttl);
  ASSERT_EQ(rt, node_->KeyLastRefreshTime(key, value));
  ASSERT_EQ(et, node_->KeyExpireTime(key, value));
  ASSERT_EQ(ttl, node_->KeyValueTTL(key, value));
  std::vector<std::string> values;
  ASSERT_TRUE(node_->FindValueLocal(key, &values));
  ASSERT_EQ(size_t(1), values.size());
  ASSERT_EQ(value, values.at(0));
}

TEST_F(TestKnodeFunctions, BEH_KNODE_CheckContactLocalAddress) {
  KadId key(KadId::kRandomId);
  Contact c(key, "127.0.0.1", 5000, "127.0.0.1", 0), n, o;
  if (!node_->GetContact(key, &n))
    ASSERT_EQ(0, node_->AddContact(c, 1.0f, false));

  ASSERT_EQ(REMOTE, node_->CheckContactLocalAddress(c.node_id(), "", 0, ""));
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  node_->UpdatePDRTContactToRemote(key, local_ip.to_string());
  ASSERT_TRUE(node_->GetContact(key, &o));
  ASSERT_TRUE(c.Equals(o));
//  ASSERT_EQ(local_ip.to_string(), base::IpBytesToAscii(o.host_ip()));
}

TEST_F(TestKnodeFunctions, BEH_KNODE_RpcsKeysAlternativeStoreValidator) {
  KadRpcs *rpcs = node_->kadrpcs();
  ASSERT_FALSE(NULL == rpcs);
  ASSERT_TRUE(node_->HasRSAKeys());
  base::AlternativeStore *bas = node_->alternative_store();
  ASSERT_TRUE(NULL == bas);
  TestAlternativeStore tas;
  node_->set_alternative_store(&tas);
  bas = node_->alternative_store();
  ASSERT_TRUE(NULL != bas);
  ASSERT_TRUE(&tas == bas);
  TestValidator tv;
  node_->set_signature_validator(&tv);
}

TEST_F(TestKnodeFunctions, BEH_KNODE_NodeInfo) {
  ContactInfo ci = node_->contact_info();
  KadId kid = node_->node_id();
  std::string host_ip = node_->host_ip();
  boost::uint16_t host_port = node_->host_port();
  std::string local_host_ip = node_->local_host_ip();
  boost::uint16_t local_host_port= node_->local_host_port();
  std::string rendezvous_ip = node_->rendezvous_ip();
  boost::uint16_t rendezvous_port = node_->rendezvous_port();

  ASSERT_EQ(ci.node_id(), kid.String());
  ASSERT_EQ(base::IpBytesToAscii(ci.ip()), host_ip);
  ASSERT_EQ(ci.port(), host_port);
  ASSERT_EQ(base::IpBytesToAscii(ci.local_ip()), local_host_ip);
  ASSERT_EQ(ci.local_port(), local_host_port);
  ASSERT_EQ(base::IpBytesToAscii(ci.rendezvous_ip()), rendezvous_ip);
  ASSERT_EQ(ci.rendezvous_port(), rendezvous_port);

  ASSERT_FALSE(node_->recheck_nat_type());
  ASSERT_EQ(DIRECT_CONNECTED, node_->host_nat_type());
}

}  // namespace test_kbucket

}  // namespace kad
