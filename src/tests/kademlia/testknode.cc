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

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/progress.hpp>
#include <boost/lexical_cast.hpp>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

#include <exception>
#include <vector>
#include <list>
#include <set>

#include "kademlia/knodeimpl.h"
#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "udt/udt.h"
#include "protobuf/signed_kadvalue.pb.h"
#include "maidsafe/config.h"

namespace fs = boost::filesystem;

const int kNetworkSize = 17;
const int kTestK = 16;

inline void create_rsakeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void create_req(const std::string &pub_key, const std::string &priv_key,
    const std::string &key, std::string *sig_pub_key, std::string *sig_req) {
  crypto::Crypto cobj;
  cobj.set_symm_algorithm(crypto::AES_256);
  cobj.set_hash_algorithm(crypto::SHA_512);
  *sig_pub_key = cobj.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  *sig_req = cobj.AsymSign(cobj.Hash(pub_key + *sig_pub_key + key, "",
      crypto::STRING_STRING, true), "", priv_key, crypto::STRING_STRING);
}

std::string get_app_directory() {
  boost::filesystem::path app_path;
#if defined(MAIDSAFE_POSIX)
  app_path = boost::filesystem::path("/var/cache/maidsafe/",
      boost::filesystem::native);
#elif defined(MAIDSAFE_WIN32)
  TCHAR szpth[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szpth))) {
    std::ostringstream stm;
    const std::ctype<char> &ctfacet =
        std::use_facet< std::ctype<char> >(stm.getloc());
    for (size_t i = 0; i < wcslen(szpth); ++i)
      stm << ctfacet.narrow(szpth[i], 0);
    app_path = boost::filesystem::path(stm.str(),
                                       boost::filesystem::native);
    app_path /= "maidsafe";
  }
#elif defined(MAIDSAFE_APPLE)
  app_path = boost::filesystem::path("/Library/maidsafe/", fs::native);
#endif
  return app_path.string();
}

class KNodeTest: public testing::Test {
 protected:
  KNodeTest() {}
  ~KNodeTest() {}
};

std::string kad_config_file_;
std::vector< boost::shared_ptr< transport::Transport > > transports_;
std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> >
    channel_managers_;
std::vector< boost::shared_ptr<kad::KNode> > knodes_;
std::vector<std::string> dbs_;
crypto::Crypto cry_obj_;
GeneralKadCallback cb_;
std::vector<std::string> node_ids_;
std::set<boost::uint16_t> ports_;
std::string test_dir_;

class Env: public testing::Environment {
 public:
  Env() {
    cry_obj_.set_symm_algorithm(crypto::AES_256);
    cry_obj_.set_hash_algorithm(crypto::SHA_512);
  }

  virtual ~Env() {
    transport::CleanUp();
  }

  virtual void SetUp() {
    test_dir_ = std::string("KnodeTest") +
        boost::lexical_cast<std::string>(base::random_32bit_uinteger());
    kad_config_file_ = test_dir_ + std::string("/.kadconfig");
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      fs::create_directories(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    // setup the nodes without starting them
    std::string priv_key, pub_key;
    create_rsakeys(&pub_key, &priv_key);
    for (int  i = 0; i < kNetworkSize; ++i) {
      transports_.push_back(boost::shared_ptr<transport::Transport>(new
        transport::Transport()));
      boost::shared_ptr<rpcprotocol::ChannelManager>
          channel_manager_local_(new rpcprotocol::ChannelManager(
          transports_[i].get()));
      channel_managers_.push_back(channel_manager_local_);

      std::string db_local_ = test_dir_ + std::string("/datastore") +
          boost::lexical_cast<std::string>(i);
      boost::filesystem::create_directories(db_local_);
      dbs_.push_back(db_local_);

      boost::shared_ptr<kad::KNode>
          knode_local_(new kad::KNode(channel_managers_[i].get(),
          transports_[i].get(), kad::VAULT, kTestK,
          kad::kAlpha, kad::kBeta, kad::kRefreshTime, priv_key, pub_key, false,
          false));

      EXPECT_TRUE(channel_managers_[i]->RegisterNotifiersToTransport());
      EXPECT_TRUE(transports_[i]->RegisterOnServerDown(boost::bind(
        &kad::KNode::HandleDeadRendezvousServer, knode_local_.get(), _1)));

      EXPECT_EQ(0, transports_[i]->Start(0));
      EXPECT_EQ(0, channel_managers_[i]->Start());
      knodes_.push_back(knode_local_);
      ports_.insert(knodes_[i]->host_port());
      cb_.Reset();
    }

    kad_config_file_ = dbs_[0] + "/.kadconfig";
    cb_.Reset();
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::get_local_address(&local_ip));
    knodes_[0]->Join(kad_config_file_, local_ip.to_string(),
        transports_[0]->listening_port(),
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodes_[0]->is_joined());
    LOG(INFO) << "Node 0 joined" << std::endl;
    node_ids_.push_back(knodes_[0]->node_id());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    std::string hex_id1 = base::EncodeToHex(knodes_[0]->node_id());
    kad_contact->set_node_id(hex_id1);
    kad_contact->set_ip(knodes_[0]->host_ip());
    kad_contact->set_port(knodes_[0]->host_port());
    kad_contact->set_local_ip(knodes_[0]->local_host_ip());
    kad_contact->set_local_port(knodes_[0]->local_host_port());

    for (int i = 1; i < kNetworkSize; i++) {
      kad_config_file_ = dbs_[i] + "/.kadconfig";
      std::fstream output2(kad_config_file_.c_str(),
        std::ios::out | std::ios::trunc | std::ios::binary);
      ASSERT_TRUE(kad_config.SerializeToOstream(&output2));
      output2.close();
    }

    // start the rest of the nodes (including node 1 again)
    for (int  i = 1; i < kNetworkSize; ++i) {
      cb_.Reset();
      kad_config_file_ = dbs_[i] + "/.kadconfig";
      knodes_[i]->Join(kad_config_file_,
          boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
      wait_result(&cb_);
      ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
      ASSERT_TRUE(knodes_[i]->is_joined());
      LOG(INFO) << "Node " << i << " joined" << std::endl;
      node_ids_.push_back(knodes_[i]->node_id());
    }
    cb_.Reset();
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    LOG(INFO) << kNetworkSize << " local Kademlia nodes running" << std::endl;
#ifdef WIN32
    SetConsoleTextAttribute(hconsole, 11 | 0 << 4);
#endif
  }

  virtual void TearDown() {
    boost::this_thread::sleep(boost::posix_time::seconds(5));
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 7 | 0 << 4);
#endif
    for (int i = kNetworkSize-1; i >= 1; i--) {
      transports_[i]->StopPingRendezvous();
    }
    for (int i = kNetworkSize-1; i >= 0; i--) {
      LOG(INFO) << "stopping node " << i << std::endl;
      cb_.Reset();
      knodes_[i]->Leave();
      EXPECT_FALSE(knodes_[i]->is_joined());
      transports_[i]->Stop();
      channel_managers_[i]->Stop();
    }
    std::set<boost::uint16_t>::iterator it;
    for (it = ports_.begin(); it != ports_.end(); it++) {
      // Deleting the DBs in the app dir
      fs::path db_dir(get_app_directory());
      db_dir /= boost::lexical_cast<std::string>(*it);
      try {
        if (fs::exists(db_dir))
          fs::remove_all(db_dir);
      }
      catch(const std::exception &e) {
        LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
      }
    }
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    knodes_.clear();
    channel_managers_.clear();
    transports_.clear();
    dbs_.clear();
    node_ids_.clear();
    ports_.clear();
  }
};

TEST_F(KNodeTest, FUNC_KAD_ClientKnodeConnect) {
  transport::Transport trans;
  rpcprotocol::ChannelManager channel_manager_local_(&trans);
  std::string db_local = test_dir_ + std::string("/datastore") +
      boost::lexical_cast<std::string>(kNetworkSize + 1);
  boost::filesystem::create_directories(db_local);
  std::string config_file = db_local + "/.kadconfig";
  base::KadConfig conf;
  base::KadConfig::Contact *ctc = conf.add_contact();
  std::string hex_id = base::EncodeToHex(knodes_[0]->node_id());
  ctc->set_node_id(hex_id);
  ctc->set_ip(knodes_[0]->host_ip());
  ctc->set_port(knodes_[0]->host_port());
  ctc->set_local_ip(knodes_[0]->local_host_ip());
  ctc->set_local_port(knodes_[0]->local_host_port());
  std::fstream output2(config_file.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(conf.SerializeToOstream(&output2));
  output2.close();
  std::string privkey, pubkey;
  create_rsakeys(&pubkey, &privkey);
  kad::KNode knode_local_(&channel_manager_local_, &trans, kad::CLIENT, kTestK,
    kad::kAlpha, kad::kBeta, kad::kRefreshTime, pubkey, privkey, false, false);
  EXPECT_TRUE(channel_manager_local_.RegisterNotifiersToTransport());
  EXPECT_TRUE(trans.RegisterOnServerDown(boost::bind(
    &kad::KNode::HandleDeadRendezvousServer, &knode_local_, _1)));
  ASSERT_EQ(0, trans.Start(0));
  EXPECT_EQ(0, channel_manager_local_.Start());
  ports_.insert(knode_local_.host_port());
  knode_local_.Join(config_file, boost::bind(
    &GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  // Doing a storevalue
  std::string key = cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024 * 10);  // 10KB
  kad::SignedValue sig_value;
  StoreValueCallback cb_1;
  std::string sig_pub_key, sig_req;
  create_rsakeys(&pubkey, &privkey);
  create_req(pubkey, privkey, key, &sig_pub_key, &sig_req);
  sig_value.set_value(value);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", privkey,
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  knode_local_.StoreValue(key, sig_value, pubkey, sig_pub_key,
      sig_req, 24*3600, boost::bind(&StoreValueCallback::CallbackFunc, &cb_1,
      _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());

  // loading the value with another existing node
  FindCallback cb_2;
  knodes_[11]->FindValue(key, false, boost::bind(&FindCallback::CallbackFunc,
    &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_2.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_2.values().size());
  bool got_value = false;
  for (unsigned int i = 0; i < cb_2.values().size(); i++) {
    if (value == cb_2.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // loading the value with the client
  knode_local_.FindValue(key, false, boost::bind(&FindCallback::CallbackFunc,
    &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_2.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_2.values().size());
  got_value = false;
  for (unsigned int i = 0; i < cb_2.values().size(); i++) {
    if (value == cb_2.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // Doing a find closest nodes with the client
  std::string key1 = cry_obj_.Hash("2evvnf3xssas21", "", crypto::STRING_STRING,
      false);
  FindCallback cb_3;
  knode_local_.FindCloseNodes(key1, boost::bind(
    &FindCallback::CallbackFunc, &cb_3, _1));
  wait_result(&cb_3);
  // make sure the nodes returned are what we expect.
  ASSERT_EQ(kad::kRpcResultSuccess, cb_3.result());
  ASSERT_NE(static_cast<unsigned int>(0), cb_3.closest_nodes().size());
  std::list<std::string> closest_nodes_str;  // = cb_3.closest_nodes();
  for (unsigned int i = 0; i < cb_3.closest_nodes().size(); i++)
    closest_nodes_str.push_back(cb_3.closest_nodes()[i]);
  std::list<std::string>::iterator it;
  std::list<kad::Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    kad::Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(static_cast<unsigned int>(kTestK), closest_nodes.size());
  std::list<kad::Contact> all_nodes;
  for (int i = 0; i < kNetworkSize; i++) {
    kad::Contact node(knodes_[i]->node_id(), knodes_[i]->host_ip(),
        knodes_[i]->host_port());
    all_nodes.push_back(node);
  }
  kad::SortContactList(&all_nodes, key1);
  std::list<kad::Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end();
      it1++, it2++) {
    ASSERT_TRUE(*it1 == *it2);
  }

  // Checking no node has stored the clients node in its routing table
  for (int i = 0; i < kNetworkSize; i++) {
    kad::Contact client_node;
    ASSERT_FALSE(knodes_[i]->GetContact(knode_local_.node_id(), &client_node));
  }
  cb_.Reset();
  knode_local_.Leave();
  ASSERT_FALSE(knode_local_.is_joined());
  trans.Stop();
  channel_manager_local_.Stop();
}

TEST_F(KNodeTest, FUNC_KAD_FindClosestNodes) {
  std::string key = cry_obj_.Hash("2evvnf3xssas21", "", crypto::STRING_STRING,
      false);
  FindCallback cb_1;
  knodes_[5]->FindCloseNodes(key,
      boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  // make sure the nodes returned are what we expect.
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  ASSERT_NE(static_cast<unsigned int>(0), cb_1.closest_nodes().size());
  std::list<std::string> closest_nodes_str;  // = cb_1.closest_nodes();
  for (unsigned int i = 0; i < cb_1.closest_nodes().size(); i++)
    closest_nodes_str.push_back(cb_1.closest_nodes()[i]);
  std::list<std::string>::iterator it;
  std::list<kad::Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    kad::Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(static_cast<unsigned int>(kTestK), closest_nodes.size());
  std::list<kad::Contact> all_nodes;
  for (int i = 0; i < kNetworkSize; i++) {
    kad::Contact node(knodes_[i]->node_id(), knodes_[i]->host_ip(),
        knodes_[i]->host_port(), knodes_[i]->local_host_ip(),
        knodes_[i]->local_host_port(), knodes_[i]->rv_ip(),
        knodes_[i]->rv_port());
    all_nodes.push_back(node);
  }
  kad::SortContactList(&all_nodes, key);
  std::list<kad::Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end(); it1++, it2++) {
    ASSERT_TRUE(*it1 == *it2);
  }
}

TEST_F(KNodeTest, FUNC_KAD_StoreAndLoadSmallValue) {
  // prepare small size of values
  std::string key = cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024*5);  // 5KB
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);

  knodes_[7]->StoreValue(key, sig_value, pub_key, sig_pub_key, sig_req,
      24*3600, boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultFailure, cb_.result());
  cb_.Reset();

  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  knodes_[7]->StoreValue(key, sig_value, pub_key, sig_pub_key, sig_req,
      24*3600, boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  // calculate number of nodes which hold this key/value pair
  int number = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b = false;
    knodes_[i]->FindValueLocal(key, &values);
    if (values.size() > 0) {
      for (boost::uint32_t n = 0; n < values.size() && !b; ++n) {
        kad::SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  double d = kTestK * kad::kMinSuccessfulPecentageStore;
  ASSERT_LE(static_cast<int>(d), number);
  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  knodes_[kNetworkSize - 2]->FindValue(key, false, boost::bind(
    &FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_1.values().size());
  bool got_value = false;
  for (unsigned int i = 0; i < cb_1.values().size(); i++) {
    if (value == cb_1.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }
  // load the value from no.1 node
  cb_1.Reset();
  ASSERT_TRUE(knodes_[0]->is_joined());
  knodes_[0]->FindValue(key, false, boost::bind(&FakeCallback::CallbackFunc,
    &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_1.values().size());
  got_value = false;
  for (unsigned int i = 0; i < cb_1.values().size(); i++) {
    if (value == cb_1.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node 0";
  }
  cb_1.Reset();
}

TEST_F(KNodeTest, FUNC_KAD_StoreAndLoadBigValue) {
  // prepare big size of values
  std::string key = cry_obj_.Hash("vcdrer434dccdwwt", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024 * 1024);  // 1MB
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.10 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  knodes_[10]->StoreValue(key, sig_value, pub_key, sig_pub_key, sig_req,
      24*3600, boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  // calculate number of nodes which hold this key/value pair
  int number = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    bool b = false;
    std::vector<std::string> values;
    knodes_[i]->FindValueLocal(key, &values);
    if (values.size() > 0) {
      for (boost::uint32_t n = 0; n < values.size(); ++n) {
        kad::SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  double d = kTestK * kad::kMinSuccessfulPecentageStore;
  ASSERT_LE(static_cast<int>(d), number);
  // load the value from no.10 node
  FindCallback cb_1;
  knodes_[10]->FindValue(key, false,
      boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_1.values().size());
  bool got_value = false;
  for (unsigned int i = 0; i < cb_1.values().size(); i++) {
    if (value == cb_1.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  // load the value from no.11 node
  FindCallback cb_2;
  knodes_[11]->FindValue(key, false,
      boost::bind(&FindCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_2.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_2.values().size());
  got_value = false;
  for (unsigned int i = 0; i < cb_1.values().size(); i++) {
    if (value == cb_1.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
}

TEST_F(KNodeTest, FUNC_KAD_StoreAndLoad100Values) {
  size_t count(100);
  std::vector<std::string> keys(count);
  std::vector<kad::SignedValue> values(count);
  std::vector<StoreValueCallback> cbs(count);
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  printf("Store: ");
  for (size_t n = 0; n < count; ++n) {
    keys[n] = cry_obj_.Hash("key" + base::itos(n), "", crypto::STRING_STRING,
              false);
    values[n].set_value(base::RandomString(1024));
    create_req(pub_key, priv_key, keys[n], &sig_pub_key, &sig_req);
    values[n].set_value_signature(cry_obj_.AsymSign(values[n].value(), "",
                                  priv_key, crypto::STRING_STRING));
    knodes_[n % (kNetworkSize - 1)]->StoreValue(keys[n], values[n], pub_key,
        sig_pub_key, sig_req, 24*3600,
        boost::bind(&StoreValueCallback::CallbackFunc, &cbs[n], _1));
    if (!(n % 5))
      printf(".");
  }
  printf("\nLoad:  ");
  size_t chunk_count = 0;
  int time_count = 0;
  for (size_t p = 0; p < count; ++p) {
    wait_result(&cbs[p]);
    ASSERT_EQ(kad::kRpcResultSuccess, cbs[p].result());
  }
  for (size_t p = 0; p < count; ++p) {
    FindCallback cb_1;
    knodes_[7]->FindValue(keys[p], false,
                          boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
    wait_result(&cb_1);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
    ASSERT_EQ(static_cast<unsigned int>(1), cb_1.values().size());
    ASSERT_EQ(values[p].value(), cb_1.values()[0]);
    if (!(p % 5))
      printf(".");
  }
  printf("\nDone\n");
}

TEST_F(KNodeTest, FUNC_KAD_LoadNonExistingValue) {
  std::string key = cry_obj_.Hash("bbffddnnoooo8822", "", crypto::STRING_STRING,
      false);
  // load the value from no.17 node
  FindCallback cb_1;
  knodes_[16]->FindValue(key, false,
      boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultFailure, cb_1.result());
  ASSERT_LT(0, cb_1.closest_nodes().size());
  ASSERT_EQ(0, cb_1.values().size());
}

TEST_F(KNodeTest, FUNC_KAD_FindNode) {
  // find an existing node
  std::string node_id1 = knodes_[5]->node_id();
  FindNodeCallback cb_1;
  knodes_[kNetworkSize-1]->FindNode(node_id1,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_1, _1), false);
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  kad::Contact expect_node1;
  kad::Contact target_node1(knodes_[5]->node_id(), knodes_[5]->host_ip(),
      knodes_[5]->host_port());
  expect_node1.ParseFromString(cb_1.contact());
  ASSERT_TRUE(target_node1 == expect_node1);
  // find a non-existing node
  FindNodeCallback cb_2;
  std::string node_id2 = cry_obj_.Hash("bccddde34333", "",
      crypto::STRING_STRING, false);
  knodes_[kNetworkSize-1]->FindNode(node_id2,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_2, _1), false);
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultFailure, cb_2.result());
}

TEST_F(KNodeTest, FUNC_KAD_Ping) {
  // ping by contact
  kad::Contact remote(knodes_[8]->node_id(), knodes_[8]->host_ip(),
      knodes_[8]->host_port(), knodes_[8]->local_host_ip(),
      knodes_[8]->local_host_port());
  PingCallback cb_1;
  knodes_[kNetworkSize-1]->Ping(remote,
      boost::bind(&PingCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  // ping by node id
  std::string remote_id = knodes_[9]->node_id();
  PingCallback cb_2;
  knodes_[kNetworkSize-2]->Ping(remote_id,
      boost::bind(&PingCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  // ASSERT_EQ(kad::kRpcResultSuccess, cb_2.result());
  if (kad::kRpcResultSuccess != cb_2.result()) {
    for (int i = 0; i < kNetworkSize; i++) {
      kad::Contact ctc;
      if (knodes_[i]->GetContact(remote_id, &ctc))
        printf("node %d port %d, has knodes_[9]\n", i, knodes_[i]->host_port());
    }
    if (remote_id == kad::client_node_id()) {
      printf("remote id is a client_node_id\n");
    }
    if (remote_id == knodes_[kNetworkSize-2]->node_id())
      printf("remote_id == node_id of sender\n");
    FAIL();
  }
  // ping a dead node
  std::string dead_id = cry_obj_.Hash("bb446dx", "", crypto::STRING_STRING,
      false);

  boost::uint16_t port(4242);
  std::set<boost::uint16_t>::iterator it;
  it = ports_.find(port);

  while (it != ports_.end()) {
    ++port;
    it = ports_.find(port);
  }

  kad::Contact dead_remote(dead_id, "127.0.0.1", port);
  PingCallback cb_3;
  knodes_[kNetworkSize-1]->Ping(dead_remote,
      boost::bind(&PingCallback::CallbackFunc, &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_EQ(kad::kRpcResultFailure, cb_3.result());
  PingCallback cb_4;
  knodes_[kNetworkSize-1]->Ping(dead_id,
      boost::bind(&PingCallback::CallbackFunc, &cb_4, _1));
  wait_result(&cb_4);
  ASSERT_EQ(kad::kRpcResultFailure, cb_4.result());
}

TEST_F(KNodeTest, FUNC_KAD_FindValueWithDeadNodes) {
  // Store a small value
  // prepair small size of values
  std::string key = cry_obj_.Hash("rrvvdcccdd", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(3*1024);  // 3KB
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_1;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  knodes_[8]->StoreValue(key, sig_value, pub_key, sig_pub_key, sig_req,
      24*3600, boost::bind(&FakeCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  // kill k-1 nodes, there should be at least one node left which holds this
  // value
  for (int i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    knodes_[2 + i]->Leave();
    transports_[2 + i]->Stop();
    channel_managers_[2 + i]->Stop();
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // try to find value
  // load the value from no.20 node
  FindCallback cb_2;
  knodes_[kNetworkSize - 1]->FindValue(key, false,
      boost::bind(&FakeCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_2.result());
  ASSERT_LE(static_cast<unsigned int>(1), cb_2.values().size());
  bool got_value = false;
  for (unsigned int i = 0; i < cb_2.values().size(); ++i) {
    if (value == cb_2.values()[i]) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL();
  }
  for (int i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    kad::Contact ctc(knodes_[2 + i]->node_id(), knodes_[2 + i]->host_ip(),
      knodes_[2 + i]->host_port(), knodes_[2 + i]->local_host_ip(),
      knodes_[2 + i]->local_host_port());
    PingCallback ping_cb;
    knodes_[0]->Ping(ctc, boost::bind(&PingCallback::CallbackFunc,
      &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_EQ(kad::kRpcResultFailure, ping_cb.result());
    ping_cb.Reset();
    knodes_[1]->Ping(ctc, boost::bind(&PingCallback::CallbackFunc,
      &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_EQ(kad::kRpcResultFailure, ping_cb.result());
     ping_cb.Reset();
    knodes_[kNetworkSize - 1]->Ping(ctc, boost::bind(
      &PingCallback::CallbackFunc, &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_EQ(kad::kRpcResultFailure, ping_cb.result());
  }
  // Restart dead nodes
  base::KadConfig kad_config;
  base::KadConfig::Contact *kad_contact = kad_config.add_contact();
  std::string hex_id1 = base::EncodeToHex(knodes_[0]->node_id());
  kad_contact->set_node_id(hex_id1);
  kad_contact->set_ip(knodes_[0]->host_ip());
  kad_contact->set_port(knodes_[0]->host_port());
  kad_contact->set_local_ip(knodes_[0]->local_host_ip());
  kad_contact->set_local_port(knodes_[0]->local_host_port());

  for (int i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    cb_.Reset();
    std::string conf_file = dbs_[2 + i] + "/.kadconfig";

    std::fstream output(conf_file.c_str(),
      std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output));
    output.close();

    EXPECT_TRUE(channel_managers_[2 + i]->RegisterNotifiersToTransport());
    EXPECT_TRUE(transports_[2 + i]->RegisterOnServerDown(boost::bind(
      &kad::KNode::HandleDeadRendezvousServer, knodes_[2 + i].get(), _1)));

    EXPECT_EQ(0, transports_[2 + i]->Start(0));
    EXPECT_EQ(0, channel_managers_[2 + i]->Start());

    knodes_[2 + i]->Join(node_ids_[2 + i], conf_file,
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodes_[2 + i]->is_joined());
  }
}

TEST_F(KNodeTest, FUNC_KAD_Downlist) {
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // select a random node from node 1 to node kNetworkSize
  int r_node = 1 + rand() % (kNetworkSize - 1);  // NOLINT (Fraser)
  boost::uint16_t r_port = knodes_[r_node]->host_port();
  std::string r_node_id = knodes_[r_node]->node_id();
  // Compute the sum of the nodes whose routing table contain r_node
  int sum_0 = 0;
  std::vector<int> holders;
  for (int i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      kad::Contact test_contact;
      if (knodes_[i]->GetContact(r_node_id, &test_contact)) {
        if (test_contact.failed_rpc() == kad::kFailedRpc) {
          sum_0++;
          holders.push_back(i);
        }
      }
    }
  }
  cb_.Reset();
  // finding the closest node to the dead node
  int closest_node = 0;
  kad::BigInt smallest_distance = kad::kademlia_distance(r_node_id,
    knodes_[holders[0]]->node_id());
  for (unsigned int i = 1; i < holders.size(); i++) {
    kad::BigInt distance = kad::kademlia_distance(r_node_id,
      knodes_[holders[i]]->node_id());
    if (smallest_distance > distance) {
      smallest_distance = distance;
      closest_node = i;
    }
  }

  kad::Contact holder(knodes_[holders[closest_node]]->node_id(),
    knodes_[holders[closest_node]]->host_ip(),
    knodes_[holders[closest_node]]->host_port(),
    knodes_[holders[closest_node]]->local_host_ip(),
    knodes_[holders[closest_node]]->local_host_port());
  PingCallback cb_3;
  knodes_[0]->Ping(holder,
    boost::bind(&PingCallback::CallbackFunc, &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_3.result());

  FindNodeCallback cb_1;
  kad::Contact dead_node(r_node_id, knodes_[r_node]->host_ip(),
    knodes_[r_node]->host_port(), knodes_[r_node]->local_host_ip(),
    knodes_[r_node]->local_host_port());
  PingCallback cb_2;
  knodes_[0]->Ping(dead_node,
      boost::bind(&PingCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_2.result());
  // Kill r_node
  GeneralKadCallback cb_;
  knodes_[r_node]->Leave();
  ASSERT_FALSE(knodes_[r_node]->is_joined());
  transports_[r_node]->Stop();
  channel_managers_[r_node]->Stop();
  ports_.erase(r_port);

  // Do a find node
  knodes_[0]->FindCloseNodes(r_node_id,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  // Wait for a RPC timeout interval until the downlist are handled in the
  // network
  boost::this_thread::sleep(boost::posix_time::seconds(
      rpcprotocol::kRpcTimeout/1000));
  // Compute the sum of the nodes whose routing table contain r_node again
  int sum_1 = 0;
  for (int i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      kad::Contact test_contact;
      if (knodes_[i]->GetContact(r_node_id, &test_contact)) {
        std::string enc_id = base::EncodeToHex(knodes_[i]->node_id());
        sum_1++;
      } else {
        if (test_contact.failed_rpc() > kad::kFailedRpc)
          sum_1++;
      }
    }
  }
  // r_node should be removed from the routing tables of some nodes
  ASSERT_LT(sum_1, sum_0);

  // Restart dead node
  ASSERT_TRUE(channel_managers_[r_node]->RegisterNotifiersToTransport());
  ASSERT_TRUE(transports_[r_node]->RegisterOnServerDown(boost::bind(
    &kad::KNode::HandleDeadRendezvousServer, knodes_[r_node].get(), _1)));
  ASSERT_EQ(0, transports_[r_node]->Start(0));
  ASSERT_EQ(0, channel_managers_[r_node]->Start());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  knodes_[r_node]->Join(node_ids_[r_node], conf_file,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[r_node]->is_joined());
  ports_.insert(knodes_[r_node]->host_port());
}

TEST_F(KNodeTest, FUNC_KAD_StoreWithInvalidRequest) {
  std::string key = cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024);  // 1KB
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  knodes_[7]->StoreValue(key, sig_value, pub_key, sig_pub_key, "bad request",
      24*3600, boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultFailure, cb_.result());
  std::string new_pub_key, new_priv_key;
  create_rsakeys(&new_pub_key, &new_priv_key);
  ASSERT_NE(pub_key, new_pub_key);
  cb_.Reset();
  knodes_[7]->StoreValue(key, sig_value, new_pub_key, sig_pub_key, sig_req,
      24*3600, boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultFailure, cb_.result());
}

TEST_F(KNodeTest, FUNC_KAD_AllDirectlyConnected) {
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<kad::Contact> exclude_contacts;
    std::vector<kad::Contact> contacts;
    knodes_[i]->GetRandomContacts(kNetworkSize, exclude_contacts, &contacts);
    ASSERT_LT(0, static_cast<int>(contacts.size()));
    for (int j = 0; j < static_cast<int>(contacts.size()); j++) {
      ASSERT_EQ(std::string(""), contacts[j].rendezvous_ip());
      ASSERT_EQ(0, contacts[j].rendezvous_port());
    }
  }
}

TEST_F(KNodeTest, FUNC_KAD_IncorrectNodeLocalAddrPing) {
  kad::Contact remote(knodes_[8]->node_id(), knodes_[8]->host_ip(),
      knodes_[8]->host_port(), knodes_[8]->local_host_ip(),
      knodes_[8]->local_host_port());
  PingCallback cb_1;
  knodes_[4]->Ping(remote,
      boost::bind(&PingCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());

  // now ping the node that has changed its local address
  kad::Contact remote1(knodes_[4]->node_id(), knodes_[4]->host_ip(),
      knodes_[4]->host_port(), knodes_[6]->local_host_ip(),
      knodes_[6]->local_host_port());
  cb_1.Reset();
  knodes_[8]->Ping(remote1,
      boost::bind(&PingCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
}

TEST_F(KNodeTest, FUNC_KAD_FindDeadNode) {
  // find an existing node that has gone down
  // select a random node from node 1 to node kNetworkSize
  int r_node = 1 + rand() % (kNetworkSize - 2);  // NOLINT (Fraser)
  printf("+++++++++++++++++ r_node = %d \n", r_node);
  std::string r_node_id = knodes_[r_node]->node_id();
  boost::uint16_t r_port = knodes_[r_node]->host_port();
  knodes_[r_node]->Leave();
  ASSERT_FALSE(knodes_[r_node]->is_joined());
  transports_[r_node]->Stop();
  channel_managers_[r_node]->Stop();
  ports_.erase(r_port);
  // Do a find node
  printf("+++++++++++++++++ Node %d stopped\n", r_node);
  FindNodeCallback cb_1;
  knodes_[kNetworkSize - 1]->FindNode(r_node_id,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_1, _1), false);
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultFailure, cb_1.result());
  boost::this_thread::sleep(boost::posix_time::seconds(3*
      (rpcprotocol::kRpcTimeout/1000+1)));
  // Restart dead node
  printf("+++++++++++++++++Restarting %d \n", r_node);
  ASSERT_TRUE(channel_managers_[r_node]->RegisterNotifiersToTransport());
  ASSERT_TRUE(transports_[r_node]->RegisterOnServerDown(boost::bind(
    &kad::KNode::HandleDeadRendezvousServer, knodes_[r_node].get(), _1)));
  ASSERT_EQ(0, transports_[r_node]->Start(0));
  ASSERT_EQ(0, channel_managers_[r_node]->Start());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  knodes_[r_node]->Join(node_ids_[r_node], conf_file,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[r_node]->is_joined());
  ports_.insert(knodes_[r_node]->host_port());
}

TEST_F(KNodeTest, FUNC_KAD_StartStopNode) {
  int r_node = 1 + rand() % (kNetworkSize - 1);  // NOLINT (Fraser)
  std::string kadconfig_path(dbs_[r_node] + "/.kadconfig");
  knodes_[r_node]->Leave();
  EXPECT_FALSE(knodes_[r_node]->is_joined());
  // Checking kadconfig file
  base::KadConfig kconf;
  ASSERT_TRUE(boost::filesystem::exists(
      boost::filesystem::path(kadconfig_path)));
  std::ifstream kadconf_file(kadconfig_path.c_str(),
      std::ios::in | std::ios::binary);
  ASSERT_TRUE(kconf.ParseFromIstream(&kadconf_file));
  kadconf_file.close();
  ASSERT_LT(0, kconf.contact_size());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  knodes_[r_node]->Join(knodes_[r_node]->node_id(), conf_file,
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[r_node]->is_joined());
  cb_.Reset();
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(new Env);
  return RUN_ALL_TESTS();
}
