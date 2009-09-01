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
#include <boost/filesystem.hpp>
#include "kademlia/kadservice.h"
#include "kademlia/knodeimpl.h"
#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "protobuf/signed_kadvalue.pb.h"
#include "maidsafe/config.h"

namespace fs = boost::filesystem;

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

namespace kad {

class Callback {
 public:
  void CallbackFunction() {}
};

class KadServicesTest: public testing::Test {
 protected:
  KadServicesTest() : kad_config_file_(""),
      channel_manager_(new rpcprotocol::ChannelManager), knodeimpl_(),
      cb_(), contact_(), crypto_(), node_id_(""), remote_node_id_(""),
      service_(), datastore_(), routingtable_(), test_dir_("") {
    test_dir_ = std::string("KadServicesTest") +
                boost::lexical_cast<std::string>(base::random_32bit_uinteger());
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      fs::create_directories(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem exception: " << e.what() << std::endl;
    }
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    std::string datastore("/datastore");
    datastore = test_dir_ + datastore;
    std::string priv_key, pub_key;
    CreateRSAKeys(&pub_key, &priv_key);
    knodeimpl_ = boost::shared_ptr<KNodeImpl>
        (new KNodeImpl(channel_manager_, VAULT, priv_key, pub_key, false,
        false));
    std::string hex_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaa01";
    base::decode_from_hex(hex_id, &node_id_);
    hex_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
             "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    base::decode_from_hex(hex_id, &remote_node_id_);
    contact_.set_node_id(remote_node_id_);
    contact_.set_ip("127.0.0.1");
    contact_.set_port(1234);
    contact_.set_local_ip("127.0.0.2");
    contact_.set_local_port(1235);
    contact_.set_rv_ip("127.0.0.3");
    contact_.set_rv_port(1236);
  }

  virtual ~KadServicesTest() {
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem exception: " << e.what() << std::endl;
    }
  }

  virtual void SetUp() {
    EXPECT_EQ(0, channel_manager_->StartTransport(0,
        boost::bind(&kad::KNodeImpl::HandleDeadRendezvousServer,
        knodeimpl_.get(), _1)));
    cb_.Reset();
    kad_config_file_ = test_dir_ + std::string("/.kadconfig");
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::get_local_address(&local_ip));
    knodeimpl_->Join(node_id_, kad_config_file_,
        local_ip.to_string(), channel_manager_->ptransport()->listening_port(),
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodeimpl_->is_joined());
    cb_.Reset();
    service_ = knodeimpl_->premote_service_;
    datastore_ = knodeimpl_->pdata_store_;
    routingtable_ = knodeimpl_->prouting_table_;
  }

  virtual void TearDown() {
    cb_.Reset();
    knodeimpl_->Leave();
    EXPECT_FALSE(knodeimpl_->is_joined());
    knodeimpl_.reset();
    service_.reset();
    datastore_.reset();
    routingtable_.reset();
    channel_manager_->StopTransport();
    channel_manager_->CleanUpTransport();
    channel_manager_.reset();
  }
  std::string kad_config_file_;
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
  boost::shared_ptr<KNodeImpl> knodeimpl_;
  GeneralKadCallback cb_;
  ContactInfo contact_;
  crypto::Crypto crypto_;
  std::string node_id_;
  std::string remote_node_id_;
  boost::shared_ptr<KadService> service_;
  boost::shared_ptr<DataStore> datastore_;
  boost::shared_ptr<RoutingTable> routingtable_;
  std::string test_dir_;
 private:
  KadServicesTest(const KadServicesTest&);
  KadServicesTest &operator=(const KadServicesTest&);
};

TEST_F(KadServicesTest, BEH_KAD_ServicesValidateSignedRequest) {
  std::string public_key("A"), private_key("B"), key("C");
  std::string signed_public_key, signed_request;
  CreateSignedRequest(public_key, private_key, key, &signed_public_key,
                      &signed_request);
  EXPECT_FALSE(service_->ValidateSignedRequest(public_key, signed_public_key,
                                               signed_request, key));
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &signed_public_key,
                      &signed_request);
  EXPECT_TRUE(service_->ValidateSignedRequest(public_key, signed_public_key,
                                              signed_request, key));
}

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
  EXPECT_FALSE(routingtable_->GetContact(remote_node_id_, &contactback));
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
  EXPECT_TRUE(routingtable_->GetContact(remote_node_id_, &contactback));
}

TEST_F(KadServicesTest, BEH_KAD_ServicesFindValue) {
  // Search in empty routing table and datastore
  rpcprotocol::Controller controller;
  FindRequest find_value_request;
  std::string hex_key, public_key, private_key;
  CreateRSAKeys(&public_key, &private_key);
  for (int i = 0; i < 128; ++i)
    hex_key += "a";
  std::string key;
  base::decode_from_hex(hex_key, &key);
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
  EXPECT_TRUE(routingtable_->GetContact(remote_node_id_, &contactback));
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
    hex_id += base::itos(i+10);
    std::string id("");
    base::decode_from_hex(hex_id, &id);
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
  std::string wrong_key;
  base::decode_from_hex(wrong_hex_key, &wrong_key);
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
    values.push_back("Value"+base::itos(i));
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
  std::string key;
  base::decode_from_hex(hex_key, &key);
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
  EXPECT_TRUE(routingtable_->GetContact(remote_node_id_, &contactback));
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
      hex_id = crypto_.Hash(base::itos(r), "", crypto::STRING_STRING, true);
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
    std::string id;
    base::decode_from_hex(hex_id, &id);
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
    hex_id += base::itos(i+10);
    std::string id("");
    base::decode_from_hex(hex_id, &id);
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
  std::string key, value1("Val1"), value2("Val2"), value3("Val10");
  std::string public_key, private_key, signed_public_key, signed_request;
  base::decode_from_hex(hex_key, &key);
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
  ASSERT_TRUE(datastore_->LoadItem(key, values));
  EXPECT_EQ(ser_sig_value1, values[0]);
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(remote_node_id_, &contactback));

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
  EXPECT_TRUE(datastore_->LoadItem(key, values));
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
  EXPECT_TRUE(datastore_->LoadItem(key, values));
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
  EXPECT_FALSE(datastore_->LoadItem(key, values));

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

  store_request.set_public_key(public_key);
  store_request.set_signed_public_key(signed_public_key);
  store_request.set_signed_request(signed_request);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done2);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, store_response.result());
  EXPECT_EQ(node_id_, store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, values));
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
  EXPECT_TRUE(datastore_->LoadItem(key, values));
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
  EXPECT_TRUE(datastore_->LoadItem(key1, values));
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
  EXPECT_TRUE(datastore_->LoadItem(key1, values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(ser_sig_value1, values[0]);
}

TEST_F(KadServicesTest, FUNC_KAD_ServicesDownlist) {
  // Set up details of 10 nodes and add 7 of these to the routing table.
  std::vector<Contact> contacts;
  for (int i = 0; i < 10; ++i) {
    std::string character = base::itos(i);
    std::string hex_id, id;
    for (int j = 0; j < 128; ++j)
      hex_id += character;
    ASSERT_TRUE(base::decode_from_hex(hex_id, &id));
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
    ASSERT_FALSE(knodeimpl_->GetContact(contacts[i].node_id(), &ctc));
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
  ASSERT_TRUE(knodeimpl_->GetContact(contacts[5].node_id(), &ctc));
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
}  // namespace kad
