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
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

#include <exception>
#include <vector>
#include <list>

#include "base/crypto.h"
#include "base/rsakeypair.h"
#include "kademlia/kadutils.h"
#include "kademlia/knodeimpl.h"
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "transport/transportapi.h"

namespace fs = boost::filesystem;

const int kNetworkSize = 20;
const int kTestK = 4;

inline void create_rsakeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(512);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void create_req(const std::string &pub_key, const std::string &priv_key,
  const std::string &key, std::string *sig_pub_key, std::string *sig_req) {
  crypto::Crypto cobj;
  cobj.set_symm_algorithm("AES_256");
  cobj.set_hash_algorithm("SHA512");
  *sig_pub_key = cobj.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  *sig_req = cobj.AsymSign(cobj.Hash(pub_key + *sig_pub_key + key, "",
      crypto::STRING_STRING, true), "", priv_key, crypto::STRING_STRING);
}

class KNodeTest: public testing::Test {
 protected:
  KNodeTest() {}
  virtual ~KNodeTest() {}
 private:
  KNodeTest(const KNodeTest&);
  KNodeTest &operator=(const KNodeTest&);
};

std::string kad_config_file("");
std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> >
    channel_managers_;
std::vector< boost::shared_ptr<kad::KNode> > knodes_;
std::vector<std::string> dbs_;
crypto::Crypto cry_obj_;
GeneralKadCallback cb_;
std::vector<std::string> node_ids;

class Env: public testing::Environment {
 public:
  Env() {
    kad_config_file = "KnodeTest/.kadconfig";
    cry_obj_.set_symm_algorithm("AES_256");
    cry_obj_.set_hash_algorithm("SHA512");
  }

  virtual ~Env() {
    UDT::cleanup();
  }

  virtual void SetUp() {
    try {
      if (fs::exists("KnodeTest"))
        fs::remove_all("KnodeTest");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    fs::create_directories("KnodeTest");
    // setup the nodes without starting them
    for (int  i = 0; i < kNetworkSize; ++i) {
      // Deleting the DBs in the app dir
      boost::filesystem::path app_path("");
#if defined(MAIDSAFE_POSIX)
      app_path = boost::filesystem::path("/var/cache/maidsafe/",
        boost::filesystem::native);
#elif defined(MAIDSAFE_WIN32)
      TCHAR szpth[MAX_PATH];
      if (SUCCEEDED(SHGetFolderPath(NULL,
                                    CSIDL_COMMON_APPDATA,
                                    NULL,
                                    0,
                                    szpth))) {
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
      app_path /= base::itos(62000 + i);
      try {
        if (fs::exists(app_path))
          fs::remove_all(app_path);
      }
      catch(const std::exception &e_) {
        printf("%s\n", e_.what());
      }
      boost::shared_ptr<rpcprotocol::ChannelManager>
          channel_manager_local_(new rpcprotocol::ChannelManager());
      channel_managers_.push_back(channel_manager_local_);

      std::string db_local_ = "KnodeTest/datastore"+base::itos(62000+i);
      dbs_.push_back(db_local_);

      boost::shared_ptr<kad::KNode>
          knode_local_(new kad::KNode(dbs_[i],
                                      channel_managers_[i],
                                      kad::VAULT,
                                      kTestK,
                                      kad::kAlpha,
                                      kad::kBeta));
      EXPECT_EQ(0, channel_managers_[i]->StartTransport(62000+i,
        boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode_local_.get(),
                    _1, _2, _3)));
      knodes_.push_back(knode_local_);
      cb_.Reset();
    }

    // Delete the app file for the client node on port 63001
    boost::filesystem::path app_path("");
#if defined(MAIDSAFE_POSIX)
    app_path = boost::filesystem::path("/var/cache/maidsafe/",
      boost::filesystem::native);
#elif defined(MAIDSAFE_WIN32)
    TCHAR szpth[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_COMMON_APPDATA,
                                  NULL,
                                  0,
                                  szpth))) {
      std::ostringstream stm;
      const std::ctype<char> &ctfacet =
          std::use_facet< std::ctype<char> >(stm.getloc());
      for (size_t i = 0; i < wcslen(szpth); ++i)
        stm << ctfacet.narrow(szpth[i], 0);
      app_path = boost::filesystem::path(stm.str(), boost::filesystem::native);
      app_path /= "maidsafe";
    }
#elif defined(MAIDSAFE_APPLE)
    app_path = boost::filesystem::path("/Library/maidsafe/", fs::native);
#endif
    app_path /= base::itos(63001);
    try {
      if (fs::exists(app_path))
        fs::remove_all(app_path);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }

    // start node 1 and add his details to kad config protobuf
    kad_config_file = dbs_[1] + "/.kadconfig";
    knodes_[1]->Join("",
                     kad_config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1),
                     false);
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodes_[1]->is_joined());
    printf("Node 1 joined.\n");
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact_ = kad_config.add_contact();
    std::string hex_id;
    base::encode_to_hex(knodes_[1]->node_id(), hex_id);
    kad_contact_->set_node_id(hex_id);
    kad_contact_->set_ip(knodes_[1]->host_ip());
    kad_contact_->set_port(knodes_[1]->host_port());
    kad_contact_->set_local_ip(knodes_[1]->local_host_ip());
    kad_contact_->set_local_port(knodes_[1]->local_host_port());
    std::string node1_id = knodes_[1]->node_id();
    kad_config_file = dbs_[0] + "/.kadconfig";
    std::fstream output1(kad_config_file.c_str(),
      std::ios::out | std::ios::trunc | std::ios::binary);
    EXPECT_TRUE(kad_config.SerializeToOstream(&output1));
    output1.close();

    // bootstrap node 0 (off node 1) and reset kad config with his details
    cb_.Reset();
    knodes_[0]->Join("",
                     kad_config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1),
                     false);
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodes_[0]->is_joined());
    printf("Node 0 joined.\n");
    node_ids.push_back(knodes_[0]->node_id());
    kad_config.Clear();
    kad_contact_ = kad_config.add_contact();
    std::string hex_id1;
    base::encode_to_hex(knodes_[0]->node_id(), hex_id1);
    kad_contact_->set_node_id(hex_id1);
    kad_contact_->set_ip(knodes_[0]->host_ip());
    kad_contact_->set_port(knodes_[0]->host_port());
    kad_contact_->set_local_ip(knodes_[0]->local_host_ip());
    kad_contact_->set_local_port(knodes_[0]->local_host_port());

    for (int i = 1; i < kNetworkSize; i++) {
      kad_config_file = dbs_[i] + "/.kadconfig";
      std::fstream output2(kad_config_file.c_str(),
        std::ios::out | std::ios::trunc | std::ios::binary);
      ASSERT_TRUE(kad_config.SerializeToOstream(&output2));
      output2.close();
    }

    // stop node 1
    cb_.Reset();
    knodes_[1]->Leave();
    EXPECT_FALSE(knodes_[1]->is_joined());
    printf("Node 1 left.\n");

    // start the rest of the nodes (including node 1 again)
    for (int  i = 1; i < kNetworkSize; ++i) {
      std::string id("");
      if (i == 1) {
        id = node1_id;
      }
      cb_.Reset();
      kad_config_file = dbs_[i] + "/.kadconfig";
      knodes_[i]->Join(id,
                       kad_config_file,
                       boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1),
                       false);
      wait_result(&cb_);
      ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
      ASSERT_TRUE(knodes_[i]->is_joined());
      printf("Node %i joined.\n", i);
      node_ids.push_back(knodes_[i]->node_id());
    }
    cb_.Reset();
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    printf("*-----------------------------------*\n");
    printf("*  %i local Kademlia nodes running  *\n", kNetworkSize);
    printf("*-----------------------------------*\n\n");
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
    printf("In tear down.\n");
    for (int i = kNetworkSize-1; i >= 1; i--) {
      knodes_[i]->StopRvPing();
    }
    for (int i = kNetworkSize-1; i >= 0; i--) {
      printf("stopping node %i\n", i);
      cb_.Reset();
      knodes_[i]->Leave();
      EXPECT_FALSE(knodes_[i]->is_joined());
      channel_managers_[i]->StopTransport();
      knodes_[i].reset();
      channel_managers_[i].reset();
      // Deleting the DBs in the app dir
      boost::filesystem::path app_path("");
#if defined(MAIDSAFE_POSIX)
      app_path = boost::filesystem::path("/var/cache/maidsafe/",
        boost::filesystem::native);
#elif defined(MAIDSAFE_WIN32)
      TCHAR szpth[MAX_PATH];
      if (SUCCEEDED(SHGetFolderPath(NULL,
                                    CSIDL_COMMON_APPDATA,
                                    NULL,
                                    0,
                                    szpth))) {
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
      app_path /= base::itos(62000 + i);
      try {
        if (fs::exists(app_path))
          fs::remove_all(app_path);
      }
      catch(const std::exception &e_) {
        printf("%s\n", e_.what());
      }
    }
    boost::filesystem::path app_path("");
#if defined(MAIDSAFE_POSIX)
    app_path = boost::filesystem::path("/var/cache/maidsafe/",
      boost::filesystem::native);
#elif defined(MAIDSAFE_WIN32)
    TCHAR szpth[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_COMMON_APPDATA,
                                  NULL,
                                  0,
                                  szpth))) {
      std::ostringstream stm;
      const std::ctype<char> &ctfacet =
          std::use_facet< std::ctype<char> >(stm.getloc());
      for (size_t i = 0; i < wcslen(szpth); ++i)
        stm << ctfacet.narrow(szpth[i], 0);
      app_path = boost::filesystem::path(stm.str(), boost::filesystem::native);
      app_path /= "maidsafe";
    }
#elif defined(MAIDSAFE_APPLE)
    app_path = boost::filesystem::path("/Library/maidsafe/", fs::native);
#endif
    app_path /= base::itos(63001);
    try {
      if (fs::exists(app_path))
        fs::remove_all(app_path);
      if (fs::exists("KnodeTest"))
        fs::remove_all("KnodeTest");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    knodes_.clear();
    channel_managers_.clear();
    dbs_.clear();
    node_ids.clear();
    printf("Finished tear down.\n");
  }

 private:
  Env(const Env&);
  Env &operator=(const Env&);
};

TEST_F(KNodeTest, BEH_KAD_ClientKnodeConnect) {
  boost::shared_ptr<boost::mutex>
      mutex_local_(new boost::mutex);
  boost::shared_ptr<rpcprotocol::ChannelManager>
      channel_manager_local_(new rpcprotocol::ChannelManager());
  std::string db_local = "KnodeTest/datastore"+base::itos(63001);
  boost::filesystem::create_directories(db_local);
  std::string config_file = db_local + "/.kadconfig";
  base::KadConfig conf;
  base::KadConfig::Contact *ctc = conf.add_contact();
  std::string hex_id;
  base::encode_to_hex(knodes_[0]->node_id(), hex_id);
  ctc->set_node_id(hex_id);
  ctc->set_ip(knodes_[0]->host_ip());
  ctc->set_port(knodes_[0]->host_port());
  ctc->set_local_ip(knodes_[0]->local_host_ip());
  ctc->set_local_port(knodes_[0]->local_host_port());
  std::fstream output2(config_file.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(conf.SerializeToOstream(&output2));
  output2.close();

  boost::scoped_ptr<kad::KNode> knode_local_(new kad::KNode(db_local,
                                             channel_manager_local_,
                                             kad::CLIENT,
                                             kTestK,
                                             kad::kAlpha,
                                             kad::kBeta));
  EXPECT_EQ(0, channel_manager_local_->StartTransport(63001,
    boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode_local_.get(),
                _1, _2, _3)));
  knode_local_->Join("",
                     config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1),
                     false);
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  // Doing a storevalue
  std::string key = cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024*10);  // 10KB
  StoreValueCallback cb_1;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knode_local_->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());

  // loading the value with another existing node
  FindCallback cb_2;
  knodes_[11]->FindValue(key, boost::bind(&FindCallback::CallbackFunc,
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
  knode_local_->FindValue(key, boost::bind(&FindCallback::CallbackFunc,
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
  knode_local_->FindCloseNodes(key1,
      boost::bind(&FindCallback::CallbackFunc, &cb_3, _1));
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
    ASSERT_FALSE(knodes_[i]->GetContact(knode_local_->node_id(), &client_node));
  }
  cb_.Reset();
  knode_local_->Leave();
  ASSERT_FALSE(knode_local_->is_joined());
  channel_manager_local_->StopTransport();
}

TEST_F(KNodeTest, BEH_KAD_FindClosestNodes) {
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
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end();
      it1++, it2++) {
    ASSERT_TRUE(*it1 == *it2);
  }
  printf("\n\nDone\n");
}

TEST_F(KNodeTest, BEH_KAD_StoreAndLoadSmallValue) {
  // prepare small size of values
  std::string key = cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024);  // 1KB
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[7]->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
//  printf("***********Value stored on nodes ");
  // calculate number of nodes which hold this key/value pair
  int number = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b = false;
    knodes_[i]->FindValueLocal(key, values);
    if (values.size() > 0) {
      for (boost::uint32_t n = 0; n < values.size() && !b; ++n) {
        if (value == values[n]) {
          number++;
          b = true;
        }
      }
    }
  }
//  printf(" ***********\n\n");
  ASSERT_EQ(kTestK, number);
  // load the value from no.18 node
  cb_.Reset();
  FindCallback cb_1;
  knodes_[17]->FindValue(key, boost::bind(&FindCallback::CallbackFunc,
    &cb_1, _1));
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
    printf("FAIL node 17\n");
    FAIL();
  }
//  printf("***********Found value via node 17***********\n");
  // load the value from no.1 node
  cb_1.Reset();
  ASSERT_TRUE(knodes_[0]->is_joined());
  knodes_[0]->FindValue(key, boost::bind(&FakeCallback::CallbackFunc,
                                         &cb_1,
                                         _1));
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
    printf("FAIL node 0\n");
    FAIL();
  }
  cb_1.Reset();
//  printf("***********Found value via node 0***********\n");
}

TEST_F(KNodeTest, FUNC_KAD_StoreAndLoadBigValue) {
  // prepare big size of values
  std::string key = cry_obj_.Hash("vcdrer434dccdwwt", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024*1024);  // 1MB
  // save key/value pair from no.10 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[10]->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  // calculate number of nodes which hold this key/value pair
  int number = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    bool b = false;
    std::vector<std::string> values;
    knodes_[i]->FindValueLocal(key, values);
    if (values.size() > 0) {
      for (boost::uint32_t n = 0; n < values.size(); ++n) {
        if (value == values[n]) {
          number++;
          b = true;
        }
      }
    }
  }
  ASSERT_EQ(kTestK, number);
  // load the value from no.10 node
  FindCallback cb_1;
  knodes_[10]->FindValue(key,
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
  knodes_[11]->FindValue(key,
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

TEST_F(KNodeTest, BEH_KAD_LoadNonExistingValue) {
  std::string key = cry_obj_.Hash("bbffddnnoooo8822", "", crypto::STRING_STRING,
      false);
  // load the value from no.17 node
  FindCallback cb_1;
  knodes_[16]->FindValue(key,
      boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultFailure, cb_1.result());
}

TEST_F(KNodeTest, BEH_KAD_FindNode) {
  // find an existing node
  std::string node_id1 = knodes_[5]->node_id();
  FindNodeCallback cb_1;
  knodes_[19]->FindNode(node_id1,
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
  knodes_[19]->FindNode(node_id2,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_2, _1), false);
  wait_result(&cb_2);
  ASSERT_EQ(kad::kRpcResultFailure, cb_2.result());
}

TEST_F(KNodeTest, BEH_KAD_Ping) {
  // ping by contact
  kad::Contact remote(knodes_[8]->node_id(), knodes_[8]->host_ip(),
      knodes_[8]->host_port(), knodes_[8]->local_host_ip(),
      knodes_[8]->local_host_port());
  PingCallback cb_1;
  knodes_[19]->Ping(remote,
      boost::bind(&PingCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  // ping by node id
  std::string remote_id = knodes_[9]->node_id();
  PingCallback cb_2;
  knodes_[18]->Ping(remote_id,
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
    if (remote_id == knodes_[18]->node_id())
      printf("remote_id == node_id of sender\n");
    FAIL();
  }
  // ping a dead node
  std::string dead_id = cry_obj_.Hash("bb446dx", "", crypto::STRING_STRING,
      false);
  kad::Contact dead_remote(dead_id, "127.0.0.1", 9999);
  PingCallback cb_3;
  knodes_[19]->Ping(dead_remote,
      boost::bind(&PingCallback::CallbackFunc, &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_EQ(kad::kRpcResultFailure, cb_3.result());
  PingCallback cb_4;
  knodes_[19]->Ping(dead_id,
      boost::bind(&PingCallback::CallbackFunc, &cb_4, _1));
  wait_result(&cb_4);
  ASSERT_EQ(kad::kRpcResultFailure, cb_4.result());
}

TEST_F(KNodeTest, BEH_KAD_FindValueWithDeadNodes) {
  // Store a small value
  // prepair small size of values
  std::string key = cry_obj_.Hash("rrvvdcccdd", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(3*1024);  // 3KB
  // save key/value pair from no.8 node
  StoreValueCallback cb_1;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[8]->StoreValue(key, value, pub_key, sig_pub_key, sig_req,
      boost::bind(&FakeCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  // kill k-1 nodes, there should be at least one node left which holds this
  // value
  for (int i = 0; i < kTestK - 1; ++i) {
    knodes_[2 + i]->Leave();
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // try to find value
  // load the value from no.20 node
  FindCallback cb_2;
  knodes_[19]->FindValue(key,
      boost::bind(&FakeCallback::CallbackFunc, &cb_2, _1));
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
  // Restart dead nodes
  for (int i = 0; i < kTestK - 1; ++i) {
    cb_.Reset();
    std::string conf_file = dbs_[2 + i] + "/.kadconfig";
    knodes_[2 + i]->Join(node_ids[2 + i], conf_file,
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1), false);
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodes_[2 + i]->is_joined());
  }
}

TEST_F(KNodeTest, FUNC_KAD_Downlist) {
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // select a random node from node 1 to node 19
  int r_node = 1 + rand() % 19;  // NOLINT (Fraser)
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
          printf("node %i has the dead node \n", knodes_[i]->host_port());
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
  channel_managers_[r_node]->StopTransport();
  // Do a find node
  knodes_[0]->FindCloseNodes(r_node_id,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_1.result());
  // Wait for a RPC timeout interval until the downlist are handled in the
  // network
  boost::this_thread::sleep(boost::posix_time::seconds(
      4*(rpcprotocol::kRpcTimeout/1000+1)));
  // Compute the sum of the nodes whose routing table contain r_node again
  int sum_1 = 0;
  for (int i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      kad::Contact test_contact;
      if (knodes_[i]->GetContact(r_node_id, &test_contact)) {
        std::string enc_id;
        base::encode_to_hex(knodes_[i]->node_id(), enc_id);
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
  ASSERT_EQ(0, channel_managers_[r_node]->StartTransport(62000+r_node,
      boost::bind(&kad::KNode::HandleDeadRendezvousServer,
      knodes_[r_node].get(), _1, _2, _3)));
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  knodes_[r_node]->Join(node_ids[r_node], conf_file,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1), false);
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[r_node]->is_joined());
}

TEST_F(KNodeTest, BEH_KAD_StoreWithInvalidRequest) {
  std::string key = cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING,
      false);
  std::string value = base::RandomString(1024);  // 1KB
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key(""), priv_key(""), sig_pub_key(""), sig_req("");
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key, &sig_pub_key, &sig_req);
  knodes_[7]->StoreValue(key, value, pub_key, sig_pub_key, "bad request",
      boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultFailure, cb_.result());
  std::string new_pub_key(""), new_priv_key("");
  create_rsakeys(&new_pub_key, &new_priv_key);
  ASSERT_NE(pub_key, new_pub_key);
  cb_.Reset();
  knodes_[7]->StoreValue(key, value, new_pub_key, sig_pub_key, sig_req,
      boost::bind(&StoreValueCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultFailure, cb_.result());
}

TEST_F(KNodeTest, BEH_KAD_AllDirectlyConnected) {
  for (int i = 0; i < kNetworkSize; i++) {
    std::vector<kad::Contact> exclude_contacts;
    std::vector<kad::Contact> contacts;
    knodes_[i]->GetRandomContacts(kNetworkSize, exclude_contacts, &contacts);
    ASSERT_LT(0, static_cast<int>(contacts.size()));
    for (int j = 0; j < static_cast<int>(contacts.size()); j++) {
      ASSERT_EQ("", contacts[j].rendezvous_ip());
      ASSERT_EQ(0, contacts[j].rendezvous_port());
    }
  }
}

TEST_F(KNodeTest, BEH_KAD_IncorrectNodeLocalAddrPing) {
  // knodes_[4]->set_local_port(knodes_[6]->local_port());
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

TEST_F(KNodeTest, BEH_KAD_FindDeadNode) {
  // find an existing node that has gone down
  // select a random node from node 1 to node 19
  int r_node = rand() % 19;  // NOLINT (Fraser)
  std::string r_node_id = knodes_[r_node]->node_id();
  knodes_[r_node]->Leave();
  ASSERT_FALSE(knodes_[r_node]->is_joined());
  channel_managers_[r_node]->StopTransport();
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
  // Do a find node
  FindNodeCallback cb_1;
  knodes_[19]->FindNode(r_node_id,
      boost::bind(&FindNodeCallback::CallbackFunc, &cb_1, _1), false);
  wait_result(&cb_1);
  ASSERT_EQ(kad::kRpcResultFailure, cb_1.result());
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  // Restart dead node
  ASSERT_EQ(0, channel_managers_[r_node]->StartTransport(62000+r_node,
      boost::bind(&kad::KNode::HandleDeadRendezvousServer,
      knodes_[r_node].get(), _1, _2, _3)));
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  knodes_[r_node]->Join(node_ids[r_node], conf_file,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1), false);
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[r_node]->is_joined());
}

TEST_F(KNodeTest, BEH_KAD_RebootstrapNode) {
  cb_.Reset();
  std::string db_local = "KnodeTest/datastore"+base::itos(65001);
  std::string kconf_file = db_local + "/.kadconfig";
  boost::filesystem::create_directories(db_local);
  base::KadConfig kad_config;
  base::KadConfig::Contact *kad_contact = kad_config.add_contact();
  std::string hex_id;
  base::encode_to_hex(knodes_[4]->node_id(), hex_id);
  kad_contact->set_node_id(hex_id);
  kad_contact->set_ip(knodes_[4]->host_ip());
  kad_contact->set_port(knodes_[4]->host_port());
  kad_contact->set_local_ip(knodes_[4]->local_host_ip());
  kad_contact->set_local_port(knodes_[4]->local_host_port());
  std::fstream output2(kconf_file.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(kad_config.SerializeToOstream(&output2));
  output2.close();


  boost::shared_ptr<rpcprotocol::ChannelManager> ch_man(
      new rpcprotocol::ChannelManager());
  boost::scoped_ptr<kad::KNode> node(new kad::KNode(db_local, ch_man,
      kad::VAULT, kTestK, kad::kAlpha, kad::kBeta));
  EXPECT_EQ(0, ch_man->StartTransport(65001,
        boost::bind(&kad::KNode::HandleDeadRendezvousServer, node.get(),
                    _1, _2, _3)));
  cb_.Reset();
  node->Join("", kconf_file,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1), false);
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(node->is_joined());
  cb_.Reset();
  std::string ip = knodes_[4]->host_ip();
//  boost::uint16_t port = knodes_[1]->host_port();
  knodes_[4]->Leave();
  ASSERT_FALSE(knodes_[4]->is_joined());
  channel_managers_[4]->StopTransport();
  printf("Node 4 killed\n");
  while (node->is_joined()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  printf("finished waiting to notice dead node\n");
  while (!node->is_joined()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  ASSERT_TRUE(node->is_joined());
  node->Leave();
  ch_man->StopTransport();
  // Restart dead node
  ASSERT_EQ(0, channel_managers_[4]->StartTransport(62004,
      boost::bind(&kad::KNode::HandleDeadRendezvousServer, knodes_[4].get(), _1,
      _2, _3)));
  cb_.Reset();
  std::string conf_file = dbs_[4] + "/.kadconfig";
  knodes_[4]->Join(node_ids[4], conf_file,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1), false);
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[4]->is_joined());
}

TEST_F(KNodeTest, BEH_KAD_StartStopNode) {
  int r_node = 1 + rand() % 19;  // NOLINT (Fraser)
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
    boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1), false);
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
