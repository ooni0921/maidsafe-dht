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

#include <boost/lexical_cast.hpp>
#include <gtest/gtest.h>

#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"

namespace kad {

namespace test_knodeimpl {

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

void BootstrapCallbackTestCallback(const std::string &ser_result,
                                   bool *result, bool *done) {
  BootstrapResponse br;
  *result = true;
  if (!br.ParseFromString(ser_result)) {
    *done = true;
    return;
  }

  if (!br.IsInitialized()) {
    *done = true;
    return;
  }

  if (br.result() == kRpcResultFailure) {
    *result = false;
  }
  *done = true;
}

static const boost::uint16_t K = 16;

class TestKNodeImpl : public testing::Test {
 protected:
  static void SetUpTestCase() {
    test_dir_ = std::string("temp/TestKNodeImpl") +
                boost::lexical_cast<std::string>(base::RandomUint32());

    udt_ = new transport::TransportUDT;
    handler_ = new transport::TransportHandler;
    handler_->Register(udt_, &transport_id_);
    manager_ = new rpcprotocol::ChannelManager(handler_);

    crypto::RsaKeyPair rkp;
    rkp.GenerateKeys(4096);
    node_.reset(new KNodeImpl(manager_, handler_, kad::VAULT, K, kad::kAlpha,
                          kad::kBeta, kad::kRefreshTime, rkp.private_key(),
                          rkp.public_key(), false, false));
    node_->set_transport_id(transport_id_);

    EXPECT_TRUE(manager_->RegisterNotifiersToTransport());
    EXPECT_TRUE(handler_->RegisterOnServerDown(
                    boost::bind(&kad::KNodeImpl::HandleDeadRendezvousServer,
                                node_.get(), _1)));

    EXPECT_EQ(0, handler_->Start(0, transport_id_));
    EXPECT_EQ(0, manager_->Start());

    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    boost::uint16_t lp_node;
    bool get_port;
    get_port = handler_->listening_port(transport_id_, &lp_node);
    node_->Join(test_dir_ + std::string(".kadconfig"), local_ip.to_string(),
                lp_node,
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
  static boost::shared_ptr<KNodeImpl> node_;
  static GeneralKadCallback cb_;
};

std::string TestKNodeImpl::test_dir_;
boost::int16_t TestKNodeImpl::transport_id_ = 0;
transport::TransportUDT *TestKNodeImpl::udt_ = NULL;
transport::TransportHandler *TestKNodeImpl::handler_ = NULL;
rpcprotocol::ChannelManager *TestKNodeImpl::manager_ = NULL;
boost::shared_ptr<KNodeImpl> TestKNodeImpl::node_;
GeneralKadCallback TestKNodeImpl::cb_;

TEST_F(TestKNodeImpl, BEH_KNodeImpl_ContactFunctions) {
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  KadId key1a, key2a, key1b(KadId::kRandomId), key2b(KadId::kRandomId),
        target_key(KadId::kRandomId);
  ContactAndTargetKey catk1, catk2;
  catk1.contact = Contact(key1a, local_ip.to_string(), 5001,
                          local_ip.to_string(), 5001);
  catk2.contact = Contact(key2a, local_ip.to_string(), 5002,
                          local_ip.to_string(), 5002);
  catk1.target_key = catk2.target_key = target_key;
  ASSERT_TRUE(CompareContact(catk1, catk2));
  catk1.contact = Contact(key1b, local_ip.to_string(), 5001,
                          local_ip.to_string(), 5001);
  ASSERT_FALSE(CompareContact(catk1, catk2));

  std::list<LookupContact> contact_list;
  SortLookupContact(target_key, &contact_list);
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_Destroy) {
  std::string test_dir = std::string("temp/TestKNodeImpl") +
                         boost::lexical_cast<std::string>(base::RandomUint32());

  boost::int16_t transport_id;
  transport::TransportUDT *udt = new transport::TransportUDT;
  transport::TransportHandler *handler = new transport::TransportHandler;
  handler->Register(udt, &transport_id);
  rpcprotocol::ChannelManager *manager =
      new rpcprotocol::ChannelManager(handler);

  crypto::RsaKeyPair rkp;
  rkp.GenerateKeys(4096);
  KNodeImpl *node = new KNodeImpl(manager, handler, kad::VAULT, K, kad::kAlpha,
                                  kad::kBeta, kad::kRefreshTime,
                                  rkp.private_key(), rkp.public_key(), false,
                                  true);
  node->set_transport_id(transport_id);

  EXPECT_TRUE(manager->RegisterNotifiersToTransport());
  EXPECT_TRUE(handler->RegisterOnServerDown(
                  boost::bind(&kad::KNodeImpl::HandleDeadRendezvousServer,
                              node, _1)));

  EXPECT_EQ(0, handler->Start(0, transport_id));
  EXPECT_EQ(0, manager->Start());

  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  boost::uint16_t lp_node;
  bool get_port;
  get_port = handler->listening_port(transport_id_, &lp_node);
  GeneralKadCallback cb;
  node->Join(test_dir + std::string(".kadconfig"), local_ip.to_string(),
             lp_node,
             boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb);
  ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
  ASSERT_TRUE(node->is_joined());

  delete node;
  udt->Stop();
  delete udt;
  delete handler;
  manager->ClearCallLaters();
  delete manager;
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_Bootstrap_Callback) {
  BootstrapResponse *response = new BootstrapResponse;
  struct BootstrapData data;
  bool result(false), done(false);
  data.callback = boost::bind(&BootstrapCallbackTestCallback,
                              _1, &result, &done);
  data.bootstrap_ip = "127.0.0.1";
  data.bootstrap_port = 50000;
  data.rpc_ctrler = new rpcprotocol::Controller;
  node_->Bootstrap_Callback(response, data);

  while (!done) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_FALSE(result);
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_Join_Bootstrapping_Iteration) {
  boost::shared_ptr<struct BootstrapArgs> args(new BootstrapArgs());
  args->is_callbacked = true;

  // returns if called-back
  node_->Join_Bootstrapping_Iteration_Client("", args, "", 0, "", 0);
  node_->Join_Bootstrapping_Iteration("", args, "", 0, "", 0);

  // response doesn't parse or has failure and args->active_process == 0
  GeneralKadCallback gkc;
  args->callback = boost::bind(&GeneralKadCallback::CallbackFunc, &gkc, _1);
  args->is_callbacked = false;
  args->active_process = 1;
  node_->Join_Bootstrapping_Iteration_Client("just some non-parsing nonsense",
                                             args, "", 0, "", 0);
  while (gkc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, gkc.result());

  gkc.Reset();
  args->is_callbacked = false;
  args->active_process = 1;
  node_->Join_Bootstrapping_Iteration("just some non-parsing nonsense", args,
                                      "", 0, "", 0);
  while (gkc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, gkc.result());
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_Uninitialised_Values) {
  DeleteValueCallback dvc;
  SignedValue signed_value, new_value;
  SignedRequest signed_request;
  node_->DeleteValue(KadId(KadId::kRandomId), signed_value, signed_request,
                     boost::bind(&DeleteValueCallback::CallbackFunc, &dvc, _1));
  while (dvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, dvc.result());

  UpdateValueCallback uvc;
  node_->UpdateValue(KadId(KadId::kRandomId), signed_value, new_value,
                     signed_request, 60 * 60 * 24,
                     boost::bind(&UpdateValueCallback::CallbackFunc, &uvc, _1));
  while (uvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, uvc.result());
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_ExecuteRPCs) {
  node_->is_joined_ = false;
  SignedValue old_value, new_value;
  SignedRequest sig_req;
  UpdateValueCallback uvc;
  node_->ExecuteUpdateRPCs("summat that doesn't parse", KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  ASSERT_EQ("", uvc.result());

  DeleteValueCallback dvc;
  node_->DelValue_ExecuteDeleteRPCs("summat that doesn't parse",
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  ASSERT_EQ("", dvc.result());

  dvc.Reset();
  std::vector<Contact> close_nodes;
  KadId key(KadId::kRandomId);
  SignedValue svalue;
  SignedRequest sreq;
  boost::shared_ptr<IterativeDelValueData> data(
      new struct IterativeDelValueData(close_nodes, key, svalue, sreq,
                                       boost::bind(
                                          &DeleteValueCallback::CallbackFunc,
                                          &dvc, _1)));
  data->is_callbacked = true;
  DeleteCallbackArgs callback_data(data);
  node_->DelValue_IterativeDeleteValue(NULL, callback_data);
  ASSERT_EQ("", dvc.result());

  node_->is_joined_ = true;
  uvc.Reset();
  FindResponse fr;
  fr.set_result(kRpcResultSuccess);
  std::string ser_fr, ser_c;
  Contact c(KadId(KadId::kRandomId), "127.0.0.1", 1234, "127.0.0.2", 1235,
            "127.0.0.3", 1236);
  c.SerialiseToString(&ser_c);
  int count = kMinSuccessfulPecentageStore * K - 1;
  for (int n = 0; n < count; ++n)
    fr.add_closest_nodes(ser_c);

  node_->ExecuteUpdateRPCs(fr.SerializeAsString(), KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  while (uvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, uvc.result());

  fr.set_result(kRpcResultFailure);
  uvc.Reset();
  node_->ExecuteUpdateRPCs(fr.SerializeAsString(), KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  while (uvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, uvc.result());

  dvc.Reset();
  node_->DelValue_IterativeDeleteValue(NULL, callback_data);
  ASSERT_EQ("", dvc.result());

  dvc.Reset();
  node_->DelValue_ExecuteDeleteRPCs("summat that doesn't parse",
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  while (dvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, dvc.result());

  dvc.Reset();
  fr.Clear();
  fr.set_result(kRpcResultSuccess);
  node_->DelValue_ExecuteDeleteRPCs(fr.SerializeAsString(),
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  while (dvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, dvc.result());
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_NotJoined) {
  node_->is_joined_ = false;
  node_->RefreshRoutine();

  StoreValueCallback svc;
  boost::shared_ptr<IterativeStoreValueData> isvd(
      new IterativeStoreValueData(std::vector<Contact>(), KadId(), "",
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &svc, _1),
                                  true, 3600 * 24, SignedValue(),
                                  SignedRequest()));
  ASSERT_EQ("", svc.result());
  node_->is_joined_ = true;
}

}  // namespace test_knodeimpl

}  // namespace kad
