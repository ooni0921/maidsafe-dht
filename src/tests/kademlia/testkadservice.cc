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
#include <boost/lexical_cast.hpp>
#include "kademlia/kadservice.h"
#include "kademlia/knodeimpl.h"
#include "maidsafe/alternativestore.h"
#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "protobuf/signed_kadvalue.pb.h"
#include "maidsafe/config.h"

inline void CreateRSAKeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void CreateSignedRequest(const std::string &pub_key,
    const std::string &priv_key, const std::string &key,
    std::string *sig_pub_key, std::string *sig_req) {
  crypto::Crypto cobj;
  cobj.set_symm_algorithm(crypto::AES_256);
  cobj.set_hash_algorithm(crypto::SHA_512);
  *sig_pub_key = cobj.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  *sig_req = cobj.AsymSign(cobj.Hash(pub_key + *sig_pub_key + key, "",
      crypto::STRING_STRING, true), "", priv_key, crypto::STRING_STRING);
}

class DummyAltStore : public base::AlternativeStore {
 public:
  DummyAltStore() : keys_() {}
  bool Has(const std::string &key) { return keys_.find(key) != keys_.end();}
  void Store(const std::string &key) { keys_.insert(key); }
 private:
  std::set<std::string> keys_;
};

namespace kad {

class Callback {
 public:
  void CallbackFunction() {}
};

class KadServicesTest: public testing::Test {
 protected:
  KadServicesTest() : trans_(), channel_manager_(&trans_),
      contact_(), crypto_(), node_id_(""), service_(), datastore_(),
      routingtable_() {
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    std::string priv_key, pub_key;
    CreateRSAKeys(&pub_key, &priv_key);
    std::string hex_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaa01";
    node_id_ = base::DecodeFromHex(hex_id);
    hex_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
             "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    contact_.set_node_id(base::DecodeFromHex(hex_id));
    contact_.set_ip("127.0.0.1");
    contact_.set_port(1234);
    contact_.set_local_ip("127.0.0.2");
    contact_.set_local_port(1235);
    contact_.set_rv_ip("127.0.0.3");
    contact_.set_rv_port(1236);
  }

  virtual void SetUp() {
    datastore_.reset(new DataStore(kRefreshTime));
    routingtable_.reset(new RoutingTable(node_id_));
    service_.reset(new KadService(NatRpcs(&channel_manager_, &trans_),
        datastore_, true,
        boost::bind(&KadServicesTest::AddCtc, this, _1, _2, _3),
        boost::bind(&KadServicesTest::GetRandCtcs, this, _1, _2, _3),
        boost::bind(&KadServicesTest::GetCtc, this, _1, _2),
        boost::bind(&KadServicesTest::GetKCtcs, this, _1, _2, _3),
        boost::bind(&KadServicesTest::Ping, this, _1, _2)));
    ContactInfo node_info;
    node_info.set_node_id(node_id_);
    node_info.set_ip("127.0.0.1");
    node_info.set_port(1234);
    node_info.set_local_ip("127.0.0.1");
    node_info.set_local_port(1234);
    service_->set_node_info(node_info);
    service_->set_node_joined(true);
  }

  transport::Transport trans_;
  rpcprotocol::ChannelManager channel_manager_;
  ContactInfo contact_;
  crypto::Crypto crypto_;
  std::string node_id_;
  boost::shared_ptr<KadService> service_;
  boost::shared_ptr<DataStore> datastore_;
  boost::shared_ptr<RoutingTable> routingtable_;
 private:
  int AddCtc(Contact ctc, const float&, const bool &only_db) {
    if (!only_db)
      return routingtable_->AddContact(ctc);
    return -1;
  }
  bool GetCtc(const std::string &id, Contact *ctc) {
    return routingtable_->GetContact(id, ctc);
  }
  void GetRandCtcs(const int &count, const std::vector<Contact> &ex_ctcs,
      std::vector<Contact> *ctcs) {
    ctcs->clear();
    std::vector<Contact> all_contacts;
    int kbuckets = routingtable_->KbucketSize();
    for (int i = 0; i < kbuckets; ++i) {
      std::vector<kad::Contact> contacts_i;
      routingtable_->GetContacts(i, &contacts_i, ex_ctcs);
      for (int j = 0; j < static_cast<int>(contacts_i.size()); ++j)
        all_contacts.push_back(contacts_i[j]);
    }
    if (static_cast<int>(all_contacts.size()) < count+1) {
      *ctcs = all_contacts;
      return;
    }
    std::vector<Contact> temp_vector(count);
    base::random_sample_n(all_contacts.begin(), all_contacts.end(),
      temp_vector.begin(), count);
    *ctcs = temp_vector;
  }
  void GetKCtcs(const std::string &key, std::vector<Contact> *ctcs,
      const std::vector<Contact> &ex_ctcs) {
    routingtable_->FindCloseNodes(key, K, ctcs, ex_ctcs);
  }
  void Ping(const Contact &ctc, base::callback_func_type cb) {
    boost::thread thrd(boost::bind(&KadServicesTest::ExePingCb, this,
        ctc.node_id(), cb));
  }
  void ExePingCb(const std::string &id, base::callback_func_type cb) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    routingtable_->RemoveContact(id, true);
    PingResponse resp;
    resp.set_result(kRpcResultFailure);
    cb(resp.SerializeAsString());
  }
};

TEST_F(KadServicesTest, BEH_KAD_ServicesPing) {
  // Check failure with ping set incorrectly.
  rpcprotocol::Controller controller;
  PingRequest ping_request;
  ping_request.set_ping("doink");
  ContactInfo *sender_info = ping_request.mutable_sender_info();
  *sender_info = contact_;
  PingResponse ping_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Ping(&controller, &ping_request, &ping_response, done1);
  EXPECT_TRUE(ping_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, ping_response.result());
  EXPECT_FALSE(ping_response.has_echo());
  EXPECT_EQ(node_id_, ping_response.node_id());
  Contact contactback;
  EXPECT_FALSE(routingtable_->GetContact(contact_.node_id(), &contactback));
  // Check success.
  ping_request.set_ping("ping");
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  ping_response.Clear();
  service_->Ping(&controller, &ping_request, &ping_response, done2);
  EXPECT_TRUE(ping_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, ping_response.result());
  EXPECT_EQ("pong", ping_response.echo());
  EXPECT_EQ(node_id_, ping_response.node_id());
  EXPECT_TRUE(routingtable_->GetContact(contact_.node_id(), &contactback));
}

TEST_F(KadServicesTest, BEH_KAD_ServicesFindValue) {
  // Search in empty routing table and datastore
  rpcprotocol::Controller controller;
  FindRequest find_value_request;
  std::string hex_key, public_key, private_key;
  CreateRSAKeys(&public_key, &private_key);
  for (int i = 0; i < 128; ++i)
    hex_key += "a";
  std::string key = base::DecodeFromHex(hex_key);
  find_value_request.set_key(key);
  ContactInfo *sender_info = find_value_request.mutable_sender_info();
  *sender_info = contact_;
  find_value_request.set_is_boostrap(false);
  FindResponse find_value_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->FindValue(&controller, &find_value_request, &find_value_response,
                      done1);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(contact_.node_id(), &contactback));
  // Populate routing table & datastore & search for non-existant key.  Ensure k
  // contacts have IDs close to key being searched for.
  std::vector<std::string> ids;
  for (int i = 0; i < 50; ++i) {
    std::string character = "1";
    std::string hex_id = "";
    if (i < K)
      character = "a";
    for (int j = 0; j < 126; ++j)
      hex_id += character;
    hex_id += boost::lexical_cast<std::string>(i+10);
    std::string id = base::DecodeFromHex(hex_id);
    if (i < K)
      ids.push_back(id);
    std::string ip = "127.0.0.6";
    boost::uint16_t port = 9000+i;
    Contact ctct;
    ASSERT_FALSE(routingtable_->GetContact(node_id_, &ctct));
    Contact contact(id, ip, port + i, ip, port + i);
    EXPECT_GE(routingtable_->AddContact(contact), 0);
  }
  EXPECT_GE(routingtable_->Size(), 2*K);
  std::string wrong_hex_key;
  for (int i = 0; i < 128; ++i)
    wrong_hex_key += "b";
  std::string wrong_key = base::DecodeFromHex(wrong_hex_key);
  EXPECT_TRUE(datastore_->StoreItem(wrong_key, "X", 24*3600, false));
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
                      done2);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(K, find_value_response.closest_nodes_size());

  std::vector<std::string>::iterator itr;
  for (int i = 0; i < K; ++i) {
    Contact contact;
    contact.ParseFromString(find_value_response.closest_nodes(i));
    for (itr = ids.begin(); itr < ids.end(); ++itr) {
      if (*itr == contact.node_id()) {
        ids.erase(itr);
        break;
      }
    }
  }
  EXPECT_EQ(static_cast<unsigned int>(0), ids.size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());

  // Populate datastore & search for existing key
  std::vector<std::string> values;
  for (int i = 0; i < 100; ++i) {
    values.push_back("Value"+boost::lexical_cast<std::string>(i));
    SignedValue sig_value;
    sig_value.set_value(values[i]);
    sig_value.set_value_signature(crypto_.AsymSign(values[i], "", private_key,
        crypto::STRING_STRING));
    std::string ser_sig_value = sig_value.SerializeAsString();
    EXPECT_TRUE(datastore_->StoreItem(key, ser_sig_value, 24*3600, false));
  }
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request,
                                          &find_value_response, done3);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(100, find_value_response.values_size());
  for (int i = 0; i < 100; i++) {
    bool found = false;
    for (int j = 0; j < 100; j++) {
      if (values[i] == find_value_response.values(j)) {
        found = true;
        break;
      }
    }
    if (!found)
      FAIL() << "value " << values[i] << " not in response";
  }
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());
}

TEST_F(KadServicesTest, BEH_KAD_ServicesFindNode) {
  // Search in empty routing table and datastore
  rpcprotocol::Controller controller;
  FindRequest find_node_request;
  std::string hex_key;
  for (int i = 0; i < 128; ++i)
    hex_key += "a";
  std::string key = base::DecodeFromHex(hex_key);
  find_node_request.set_key(key);
  ContactInfo *sender_info = find_node_request.mutable_sender_info();
  *sender_info = contact_;
  find_node_request.set_is_boostrap(false);
  FindResponse find_node_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->FindNode(&controller, &find_node_request, &find_node_response,
                     done1);
  EXPECT_TRUE(find_node_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_node_response.result());
  EXPECT_EQ(0, find_node_response.closest_nodes_size());
  EXPECT_EQ(0, find_node_response.values_size());
  EXPECT_FALSE(find_node_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_node_response.node_id());
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(contact_.node_id(), &contactback));
  // Populate routing table with a few random contacts (< K), ensure they are
  // not close to id to be searched for later, and ensure they are all
  // returned from the search.  Use one of these to search for later.
  std::string later_key;
  std::vector<std::string> rand_ids;
  for (int i = 0; i < K/2; ++i) {
    bool unique(false);
    std::string hex_id;
    while (!unique) {
      int r = rand();  // NOLINT (Fraser)
      hex_id = crypto_.Hash(boost::lexical_cast<std::string>(r), "",
          crypto::STRING_STRING, true);
      if (hex_id[0] == 'a')
        hex_id.replace(0, 1, "0");
      unique = true;
      if (rand_ids.size() > 0) {
        for (boost::uint32_t j = 0; j < rand_ids.size(); ++j) {
          if (rand_ids[j] == hex_id) {
            unique = false;
            break;
          }
        }
      }
      rand_ids.push_back(hex_id);
    }
    std::string id = base::DecodeFromHex(hex_id);
    later_key = id;
    std::string ip("127.0.0.11");
    boost::uint16_t port = 10101+i;
    Contact contact(id, ip, port, ip, port);
    Contact contactback;
    EXPECT_FALSE(routingtable_->GetContact(id, &contactback));
    EXPECT_EQ(routingtable_->AddContact(contact), 0);
    EXPECT_TRUE(routingtable_->GetContact(id, &contactback));
    EXPECT_EQ(id, contactback.node_id());
  }
  EXPECT_EQ((K/2) + 1, routingtable_->Size());
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_node_response.Clear();
  service_->FindNode(&controller, &find_node_request, &find_node_response,
                     done2);
  EXPECT_TRUE(find_node_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_node_response.result());
  EXPECT_EQ(K/2, find_node_response.closest_nodes_size());
  EXPECT_EQ(0, find_node_response.values_size());
  EXPECT_FALSE(find_node_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_node_response.node_id());

  // Further populate routing table & datastore & search for non-existant node.
  // Ensure k-1 contacts have IDs close to id being searched for later.
  std::vector<Contact> close_contacts;
  for (int i = 0; i < 50; ++i) {
    std::string character("1");
    std::string hex_id;
    if (i < K)
      character = "a";
    for (int j = 0; j < 126; ++j)
      hex_id += character;
    hex_id += boost::lexical_cast<std::string>(i+10);
    std::string id = base::DecodeFromHex(hex_id);
    std::string ip("127.0.0.6");
    boost::uint16_t port = 9000+i;
    Contact contact(id, ip, port + i, ip, port + i);
    if (i < K)
      close_contacts.push_back(contact);
    EXPECT_GE(routingtable_->AddContact(contact), 0);
  }
  EXPECT_GE(routingtable_->Size(), 2*K);
//  boost::int32_t now = base::get_epoch_time();
  std::string value("Value");
//  ASSERT_TRUE(datastore_->StoreItem(key, value, now, now));
  ASSERT_TRUE(datastore_->StoreItem(key, value, 24*3600, true));
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_node_response.Clear();
  service_->FindNode(&controller, &find_node_request, &find_node_response,
                     done3);
  EXPECT_TRUE(find_node_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_node_response.result());
  EXPECT_EQ(K, find_node_response.closest_nodes_size());
  std::vector<Contact> close_contacts_copy(close_contacts);
  std::vector<Contact>::iterator itr;
  for (int i = 0; i < K; ++i) {
    Contact contact;
    contact.ParseFromString(find_node_response.closest_nodes(i));
    for (itr = close_contacts_copy.begin(); itr < close_contacts_copy.end();
         ++itr) {
      if (*itr == contact) {
        close_contacts_copy.erase(itr);
        break;
      }
    }
  }
  EXPECT_EQ(static_cast<unsigned int>(0), close_contacts_copy.size());
  EXPECT_EQ(0, find_node_response.values_size());
  EXPECT_FALSE(find_node_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_node_response.node_id());

  // Search for different existing node id which is far from original one
  find_node_request.set_key(later_key);
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_node_response.Clear();

  service_->FindNode(&controller, &find_node_request, &find_node_response,
                     done4);
  EXPECT_TRUE(find_node_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_node_response.result());
  EXPECT_EQ(K, find_node_response.closest_nodes_size());
  // Check the results aren't the same as the first set and that we got the
  // actual id requested
  bool found = false;
  for (int i = 0; i < K; ++i) {
    Contact contact;
    contact.ParseFromString(find_node_response.closest_nodes(i));
    if (contact.node_id() == later_key)
      found = true;
    for (itr = close_contacts.begin(); itr < close_contacts.end(); ++itr) {
      if (*itr == contact) {
        close_contacts.erase(itr);
        break;
      }
    }
  }
  EXPECT_TRUE(found);
  EXPECT_GT(close_contacts.size(), static_cast<unsigned int>(0));
  EXPECT_EQ(0, find_node_response.values_size());
  EXPECT_FALSE(find_node_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_node_response.node_id());
}

TEST_F(KadServicesTest, BEH_KAD_ServicesStore) {
  // Store value1
  rpcprotocol::Controller controller;
  StoreRequest store_request;
  std::string hex_key;
  for (int i = 0; i < 128; ++i)
    hex_key += "a";
  std::string value1("Val1"), value2("Val2"), value3("Val10");
  std::string public_key, private_key, signed_public_key, signed_request;
  std::string key = base::DecodeFromHex(hex_key);
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &signed_public_key,
                      &signed_request);
  store_request.set_key(key);
  store_request.set_value(value1);
  store_request.set_public_key(public_key);
  store_request.set_signed_public_key(signed_public_key);
  store_request.set_signed_request(signed_request);
  store_request.set_publish(true);
  store_request.set_ttl(3600*24);
  ContactInfo *sender_info = store_request.mutable_sender_info();
  *sender_info = contact_;
  StoreResponse store_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done1);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, store_response.result());

  store_request.clear_value();

  SignedValue *svalue1 = store_request.mutable_sig_value();
  svalue1->set_value(value1);
  svalue1->set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value1 = svalue1->SerializeAsString();

  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done4);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  std::vector<std::string> values;
  ASSERT_TRUE(datastore_->LoadItem(key, &values));
  EXPECT_EQ(ser_sig_value1, values[0]);
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(contact_.node_id(), &contactback));

  // Store value2
  // Allow thread to sleep so that second value has a different last published
  // time to first value.
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  store_request.clear_sig_value();
  SignedValue *svalue2 = store_request.mutable_sig_value();
  svalue2->set_value(value2);
  svalue2->set_value_signature(crypto_.AsymSign(value2, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value2 = svalue2->SerializeAsString();
  store_response.Clear();
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done2);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  EXPECT_EQ(ser_sig_value1, values[0]);
  EXPECT_EQ(ser_sig_value2, values[1]);

  // Store value3
  // Allow thread to sleep for same reason as above.
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  store_request.clear_sig_value();
  SignedValue *svalue3 = store_request.mutable_sig_value();
  svalue3->set_value(value3);
  svalue3->set_value_signature(crypto_.AsymSign(value3, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value3 = svalue3->SerializeAsString();
  store_response.Clear();
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done3);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(3, values.size());
  int valuesfound = 0;
  for (unsigned int i = 0; i < values.size(); i++) {
    if (ser_sig_value1 == values[i]) {
      valuesfound++;
      break;
    }
  }
  for (unsigned int i = 0; i < values.size(); i++) {
    if (ser_sig_value2 == values[i]) {
      valuesfound++;
      break;
    }
  }
  for (unsigned int i = 0; i < values.size(); i++) {
    if (ser_sig_value3 == values[i]) {
      valuesfound++;
      break;
    }
  }
  ASSERT_EQ(3, valuesfound);
}

TEST_F(KadServicesTest, BEH_KAD_InvalidStoreValue) {
  std::string value("value4"), value1("value5");
  std::string key = crypto_.Hash(value, "", crypto::STRING_STRING, false);
  rpcprotocol::Controller controller;
  StoreRequest store_request;
  StoreResponse store_response;
  store_request.set_key(key);
  store_request.set_value(value);
  store_request.set_ttl(24*3600);
  store_request.set_publish(true);
  ContactInfo *sender_info = store_request.mutable_sender_info();
  *sender_info = contact_;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done1);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  store_response.Clear();
  std::vector<std::string> values;
  EXPECT_FALSE(datastore_->LoadItem(key, &values));

  std::string public_key, private_key, signed_public_key, signed_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &signed_public_key,
      &signed_request);

  store_request.clear_value();
  SignedValue *sig_value = store_request.mutable_sig_value();
  sig_value->set_value(value);
  sig_value->set_value_signature(crypto_.AsymSign(value, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value->SerializeAsString();

  store_request.set_public_key("public_key");
  store_request.set_signed_public_key(signed_public_key);
  store_request.set_signed_request(signed_request);
  google::protobuf::Closure *done6 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done6);
  EXPECT_EQ(kRpcResultFailure, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  store_response.Clear();
  values.clear();
  EXPECT_FALSE(datastore_->LoadItem(key, &values));

  store_request.clear_public_key();
  store_request.set_public_key(public_key);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done2);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(ser_sig_value, values[0]);

  store_request.clear_value();
  store_request.clear_sig_value();
  store_request.set_value("other value");
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done3);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(ser_sig_value, values[0]);

  // storing a hashable value
  store_request.Clear();
  store_response.Clear();
  SignedValue *sig_value1 = store_request.mutable_sig_value();
  sig_value1->set_value(value1);
  sig_value1->set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value1 = sig_value1->SerializeAsString();

  std::string key1 = crypto_.Hash(ser_sig_value1, "", crypto::STRING_STRING,
      false);
  ContactInfo *sender_info1 = store_request.mutable_sender_info();
  *sender_info1 = contact_;
  store_request.set_key(key1);
  store_request.set_publish(true);
  store_request.set_ttl(24*3600);
  signed_public_key = "";
  signed_request = "";
  CreateSignedRequest(public_key, private_key, key1, &signed_public_key,
      &signed_request);
  store_request.set_public_key(public_key);
  store_request.set_signed_public_key(signed_public_key);
  store_request.set_signed_request(signed_request);
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done4);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(ser_sig_value1, values[0]);

  store_request.clear_sig_value();
  SignedValue *sig_value2 = store_request.mutable_sig_value();
  sig_value2->set_value("other value");
  sig_value2->set_value_signature(crypto_.AsymSign("other value", "",
      private_key, crypto::STRING_STRING));
  std::string ser_sig_value2 = sig_value2->SerializeAsString();
  google::protobuf::Closure *done5 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done5);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(ser_sig_value1, values[0]);
}

TEST_F(KadServicesTest, FUNC_KAD_ServicesDownlist) {
  // Set up details of 10 nodes and add 7 of these to the routing table.
  std::vector<Contact> contacts;
  for (int i = 0; i < 10; ++i) {
    std::string character = boost::lexical_cast<std::string>(i);
    std::string hex_id, id;
    for (int j = 0; j < 128; ++j)
      hex_id += character;
    id = base::DecodeFromHex(hex_id);
    std::string ip("127.0.0.6");
    boost::uint16_t port = 9000 + i;
    Contact contact(id, ip, port, ip, port);
    if (i < 7)
      ASSERT_EQ(0, routingtable_->AddContact(contact));
    contacts.push_back(contact);
  }
  ASSERT_EQ(7, routingtable_->Size());

  // Check downlisting nodes we don't have returns failure
  rpcprotocol::Controller controller;
  DownlistRequest downlist_request;
  Contact ctc;
  for (int i = 7; i < 10; ++i) {
    std::string dead_node;
    ASSERT_FALSE(routingtable_->GetContact(contacts[i].node_id(), &ctc));
    if (contacts[i].SerialiseToString(&dead_node))
      downlist_request.add_downlist(dead_node);
  }
  ContactInfo *sender_info = downlist_request.mutable_sender_info();
  *sender_info = contact_;
  DownlistResponse downlist_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Downlist(&controller, &downlist_request, &downlist_response, done1);
  // Give the function time to allow any ping rpcs to timeout (they shouldn't
  // be called though)
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  EXPECT_EQ(8, routingtable_->Size());

  // Check downlist works for one we have.
  downlist_request.clear_downlist();
  std::string dead_node;
  ASSERT_TRUE(routingtable_->GetContact(contacts[5].node_id(), &ctc));
  if (contacts[5].SerialiseToString(&dead_node))
    downlist_request.add_downlist(dead_node);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  downlist_response.Clear();
  service_->Downlist(&controller, &downlist_request, &downlist_response, done2);
  int timeout = 8000;  // milliseconds
  int count = 0;
  while ((routingtable_->Size() > 6) && (count < timeout)) {
    count += 50;
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  EXPECT_EQ(7, routingtable_->Size());
  Contact testcontact;
  EXPECT_FALSE(routingtable_->GetContact(contacts[5].node_id(), &testcontact));

  // Check downlist works for one we have and one we don't.
  downlist_request.clear_downlist();
  for (int i = 6; i < 8; ++i) {
    std::string dead_node;
    if (contacts[i].SerialiseToString(&dead_node))
      downlist_request.add_downlist(dead_node);
  }
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  downlist_response.Clear();
  service_->Downlist(&controller, &downlist_request, &downlist_response, done3);
  count = 0;
  while ((routingtable_->Size() > 5) && (count < timeout)) {
    count += 50;
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  EXPECT_EQ(6, routingtable_->Size());
  EXPECT_FALSE(routingtable_->GetContact(contacts[6].node_id(), &testcontact));

  // Check downlist with multiple valid nodes
  downlist_request.clear_downlist();
  for (int i = 2; i < 5; ++i) {
    std::string dead_node;
    if (contacts[i].SerialiseToString(&dead_node))
      downlist_request.add_downlist(dead_node);
  }
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  downlist_response.Clear();
  service_->Downlist(&controller, &downlist_request, &downlist_response, done4);
  count = 0;
  while ((routingtable_->Size() > 2) && (count < timeout)) {
    count += 50;
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  EXPECT_EQ(3, routingtable_->Size());
  for (int i = 0; i < 5; ++i) {
    if (i > 1)
      EXPECT_FALSE(routingtable_->GetContact(contacts[i].node_id(),
                   &testcontact));
    else
      EXPECT_TRUE(routingtable_->GetContact(contacts[i].node_id(),
                  &testcontact));
  }
}

TEST_F(KadServicesTest, BEH_KAD_ServicesFindValueAltStore) {
  DummyAltStore dummy_alt_store;
  service_->set_alternative_store(&dummy_alt_store);
  // Search in empty alt store, routing table and datastore
  rpcprotocol::Controller controller;
  FindRequest find_value_request;
  std::string hex_key(128, 'a'), public_key, private_key;
  CreateRSAKeys(&public_key, &private_key);
  std::string key = base::DecodeFromHex(hex_key);
  find_value_request.set_key(key);
  *(find_value_request.mutable_sender_info()) = contact_;
  find_value_request.set_is_boostrap(false);
  FindResponse find_value_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->FindValue(&controller, &find_value_request, &find_value_response,
                      done1);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(contact_.node_id(), &contactback));
  // Populate routing table & datastore & search for non-existant key.  Ensure k
  // contacts have IDs close to key being searched for.
  std::vector<std::string> ids;
  for (int i = 0; i < 50; ++i) {
    std::string character = "1";
    std::string hex_id = "";
    if (i < K)
      character = "a";
    for (int j = 0; j < 126; ++j)
      hex_id += character;
    hex_id += boost::lexical_cast<std::string>(i+10);
    std::string id = base::DecodeFromHex(hex_id);
    if (i < K)
      ids.push_back(id);
    std::string ip = "127.0.0.6";
    boost::uint16_t port = 9000+i;
    Contact ctct;
    ASSERT_FALSE(routingtable_->GetContact(node_id_, &ctct));
    Contact contact(id, ip, port + i, ip, port + i);
    EXPECT_GE(routingtable_->AddContact(contact), 0);
  }
  EXPECT_GE(routingtable_->Size(), 2*K);
  std::string wrong_hex_key(128, 'b');
  std::string wrong_key = base::DecodeFromHex(wrong_hex_key);
  EXPECT_TRUE(datastore_->StoreItem(wrong_key, "X", 24*3600, false));
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
                      done2);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(K, find_value_response.closest_nodes_size());

  std::vector<std::string>::iterator itr;
  for (int i = 0; i < K; ++i) {
    Contact contact;
    contact.ParseFromString(find_value_response.closest_nodes(i));
    for (itr = ids.begin(); itr < ids.end(); ++itr) {
      if (*itr == contact.node_id()) {
        ids.erase(itr);
        break;
      }
    }
  }
  EXPECT_EQ(static_cast<unsigned int>(0), ids.size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_FALSE(find_value_response.has_alternative_value_holder());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());

  // Populate datastore & search for existing key
  std::vector<std::string> values;
  for (int i = 0; i < 100; ++i) {
    values.push_back("Value"+boost::lexical_cast<std::string>(i));
    SignedValue sig_value;
    sig_value.set_value(values[i]);
    sig_value.set_value_signature(crypto_.AsymSign(values[i], "", private_key,
        crypto::STRING_STRING));
    std::string ser_sig_value = sig_value.SerializeAsString();
    EXPECT_TRUE(datastore_->StoreItem(key, ser_sig_value, 24*3600, false));
  }
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
      done3);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(100, find_value_response.values_size());
  for (int i = 0; i < 100; ++i) {
    bool found = false;
    for (int j = 0; j < 100; ++j) {
      if (values[i] == find_value_response.values(j)) {
        found = true;
        break;
      }
    }
    if (!found)
      FAIL() << "value " << values[i] << " not in response";
  }
  EXPECT_FALSE(find_value_response.has_alternative_value_holder());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());

  // Populate alt store & search for existing key
  dummy_alt_store.Store(key);
  EXPECT_TRUE(dummy_alt_store.Has(key));
  dummy_alt_store.Store(wrong_key);
  EXPECT_TRUE(dummy_alt_store.Has(wrong_key));
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
      done4);

  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_TRUE(find_value_response.has_alternative_value_holder());
  EXPECT_EQ(node_id_, find_value_response.alternative_value_holder().node_id());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());

  find_value_request.set_key(wrong_key);
  google::protobuf::Closure *done5 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
      done5);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_TRUE(find_value_response.has_alternative_value_holder());
  EXPECT_EQ(node_id_, find_value_response.alternative_value_holder().node_id());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_, find_value_response.node_id());
}

}  // namespace kad
