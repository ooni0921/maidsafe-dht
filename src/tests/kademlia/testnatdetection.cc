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

// This tests NAT Detection and bootstrap services between three knodes, node 1
// being the newcomer, node 2 being the rendezvouz and node 3 being the contact
// which node 2 uses to test direct-connection status of node 1.

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include "kademlia/kadservice.h"
#include "kademlia/knodeimpl.h"
#include "maidsafe/maidsafe-dht.h"
#include "tests/kademlia/fake_callbacks.h"
#include "maidsafe/config.h"

namespace fs = boost::filesystem;

namespace kad {

class Callback {
 public:
  Callback() : response_() {}
  explicit Callback(BootstrapResponse *response) : response_(response) {}
  void CallbackFunction() {}
  void CallbackSendNatDet() {
    response_->set_result(kRpcResultSuccess);
  }
 private:
  BootstrapResponse *response_;
};

class NatDetectionTest: public testing::Test {
 protected:
  NatDetectionTest() : kad_config_fileA_("NatDetectionTest/A/.kadconfig"),
      kad_config_fileB_("NatDetectionTest/B/.kadconfig"),
      kad_config_fileC_("NatDetectionTest/C/.kadconfig"),
      channel_managerA_(new rpcprotocol::ChannelManager),
      channel_managerB_(new rpcprotocol::ChannelManager),
      channel_managerC_(new rpcprotocol::ChannelManager),
      knodeimpl1_(new KNodeImpl(channel_managerA_, VAULT, "", "", false,
      false)), knodeimpl2_(new KNodeImpl(channel_managerB_, VAULT, "", "",
      false, false)), knodeimpl3_(new KNodeImpl(channel_managerC_, VAULT, "",
      "", false, false)), cb_(), contactA_(), contactB_(), contactC_(),
      remote_contact_(), contact_strA_(""), contact_strB_(""),
      contact_strC_(""), node_idA_(""), node_idB_(""), node_idC_(""),
      remote_node_id_(""), serviceA_(), serviceB_(), serviceC_(), datastoreA_(),
      datastoreB_(), datastoreC_(), routingtableA_(), routingtableB_(),
      routingtableC_(), test_dir_() {
    test_dir_ = std::string("NatDetectionTest") +
                boost::lexical_cast<std::string>(base::random_32bit_uinteger());
    std::string dirs;
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      dirs = test_dir_ + std::string("/A");
      fs::create_directories(dirs);
      dirs = test_dir_ + std::string("/B");
      fs::create_directories(dirs);
      dirs = test_dir_ + std::string("/C");
      fs::create_directories(dirs);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    dirs = test_dir_ + std::string("/A/datastore");
    dirs = test_dir_ + std::string("/B/datastore");
    dirs = test_dir_ + std::string("/C/datastore");
  }

  virtual ~NatDetectionTest() {
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
  }

  virtual void SetUp() {
    // Node A.
    std::string hex_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaa01";
    base::decode_from_hex(hex_id, &node_idA_);
    ASSERT_EQ(0, channel_managerA_->StartTransport(0,
        boost::bind(&kad::KNodeImpl::HandleDeadRendezvousServer,
        knodeimpl1_.get(), _1)));
    cb_.Reset();
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::get_local_address(&local_ip));
    knodeimpl1_->Join(node_idA_, kad_config_fileA_,
        local_ip.to_string(), channel_managerA_->ptransport()->listening_port(),
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodeimpl1_->is_joined());
    serviceA_ = knodeimpl1_->premote_service_;
    datastoreA_ = knodeimpl1_->pdata_store_;
    routingtableA_ = knodeimpl1_->prouting_table_;
    contactA_ = Contact(knodeimpl1_->node_id(), knodeimpl1_->host_ip(),
                        knodeimpl1_->host_port(), knodeimpl1_->local_host_ip(),
                        knodeimpl1_->local_host_port(), knodeimpl1_->rv_ip(),
                        knodeimpl1_->rv_port());
    contactA_.SerialiseToString(&contact_strA_);

    // Node B.
    hex_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    base::decode_from_hex(hex_id, &node_idB_);
    ASSERT_EQ(0, channel_managerB_->StartTransport(0,
        boost::bind(&kad::KNodeImpl::HandleDeadRendezvousServer,
        knodeimpl2_.get(), _1)));
    cb_.Reset();
    knodeimpl2_->Join(node_idB_, kad_config_fileB_,
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodeimpl2_->is_joined());
    serviceB_ = knodeimpl2_->premote_service_;
    datastoreB_ = knodeimpl2_->pdata_store_;
    routingtableB_ = knodeimpl2_->prouting_table_;
    contactB_ = Contact(knodeimpl2_->node_id(), knodeimpl2_->host_ip(),
                        knodeimpl2_->host_port(), knodeimpl2_->local_host_ip(),
                        knodeimpl2_->local_host_port(), knodeimpl2_->rv_ip(),
                        knodeimpl2_->rv_port());
    contactB_.SerialiseToString(&contact_strB_);

    // Node C.
    hex_id = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
             "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    base::decode_from_hex(hex_id, &node_idC_);
    ASSERT_EQ(0, channel_managerC_->StartTransport(0,
        boost::bind(&kad::KNodeImpl::HandleDeadRendezvousServer,
        knodeimpl3_.get(), _1)));
    cb_.Reset();
    knodeimpl3_->Join(node_idC_, kad_config_fileC_,
        boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(knodeimpl3_->is_joined());
    serviceC_ = knodeimpl3_->premote_service_;
    datastoreC_ = knodeimpl3_->pdata_store_;
    routingtableC_ = knodeimpl3_->prouting_table_;
    contactC_ = Contact(knodeimpl3_->node_id(), knodeimpl3_->host_ip(),
                        knodeimpl3_->host_port(), knodeimpl3_->local_host_ip(),
                        knodeimpl3_->local_host_port(), knodeimpl3_->rv_ip(),
                        knodeimpl3_->rv_port());
    contactC_.SerialiseToString(&contact_strC_);

    // Add node C's details to node B's routing table
    ASSERT_EQ(routingtableB_->AddContact(contactC_), 0);

    // Set up another contact
    hex_id = "22222222222222222222222222222222222222222222222222222222222222222"
             "222222222222222222222222222222222222222222222222222222222222222";
    base::decode_from_hex(hex_id, &remote_node_id_);
    remote_contact_.set_node_id(remote_node_id_);
    remote_contact_.set_ip("127.0.0.5");
    remote_contact_.set_port(5555);
    remote_contact_.set_local_ip("127.0.0.6");
    remote_contact_.set_local_port(5556);
    remote_contact_.set_rv_ip("127.0.0.7");
    remote_contact_.set_rv_port(5557);
  }

  virtual void TearDown() {
    cb_.Reset();
    knodeimpl1_->Leave();
    EXPECT_FALSE(knodeimpl1_->is_joined());
    channel_managerA_->StopTransport();
    cb_.Reset();
    knodeimpl2_->Leave();
    EXPECT_FALSE(knodeimpl2_->is_joined());
    channel_managerB_->StopTransport();
    cb_.Reset();
    knodeimpl3_->Leave();
    EXPECT_FALSE(knodeimpl3_->is_joined());
    channel_managerC_->StopTransport();
    channel_managerC_->CleanUpTransport();
  }

  std::string kad_config_fileA_, kad_config_fileB_, kad_config_fileC_;
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_managerA_;
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_managerB_;
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_managerC_;
  boost::shared_ptr<KNodeImpl> knodeimpl1_, knodeimpl2_, knodeimpl3_;
  GeneralKadCallback cb_;
  Contact contactA_, contactB_, contactC_;
  ContactInfo remote_contact_;
  std::string contact_strA_, contact_strB_, contact_strC_;
  std::string node_idA_, node_idB_, node_idC_, remote_node_id_;
  boost::shared_ptr<KadService> serviceA_, serviceB_, serviceC_;
  boost::shared_ptr<DataStore> datastoreA_, datastoreB_, datastoreC_;
  boost::shared_ptr<RoutingTable>routingtableA_, routingtableB_, routingtableC_;
  std::string test_dir_;
 private:
  NatDetectionTest(const NatDetectionTest&);
  NatDetectionTest &operator=(const NatDetectionTest&);
};

TEST_F(NatDetectionTest, BEH_KAD_NatDetPing) {
  rpcprotocol::Controller controller;
  NatDetectionPingRequest *nd_ping_request = new NatDetectionPingRequest;
  nd_ping_request->set_ping("doink");
  ContactInfo *sender_info = nd_ping_request->mutable_sender_info();
  *sender_info = remote_contact_;
  NatDetectionPingResponse nd_ping_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  serviceA_->NatDetectionPing(&controller, nd_ping_request, &nd_ping_response,
      done1);
  EXPECT_TRUE(nd_ping_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, nd_ping_response.result());
  EXPECT_FALSE(nd_ping_response.has_echo());
  EXPECT_EQ(node_idA_, nd_ping_response.node_id());
  Contact contactback;
  EXPECT_FALSE(routingtableA_->GetContact(remote_node_id_, &contactback));
  // Check success.
  delete nd_ping_request;
  nd_ping_request = new NatDetectionPingRequest;
  nd_ping_request->set_ping("nat_detection_ping");
  sender_info = nd_ping_request->mutable_sender_info();
  *sender_info = remote_contact_;
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  nd_ping_response.Clear();
  serviceA_->NatDetectionPing(&controller, nd_ping_request, &nd_ping_response,
      done2);
  EXPECT_TRUE(nd_ping_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, nd_ping_response.result());
  EXPECT_EQ("pong", nd_ping_response.echo());
  EXPECT_EQ(node_idA_, nd_ping_response.node_id());
  EXPECT_TRUE(routingtableA_->GetContact(remote_node_id_, &contactback));
  delete nd_ping_request;
}

TEST_F(NatDetectionTest, BEH_KAD_SendNatDet) {
  // Send request to node C with node A as newcomer - should fail as node C has
  // empty routing table.
  Contact node_c;
  BootstrapResponse response;
  Callback cb_obj1(&response);
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj1, &Callback::CallbackFunction);
  std::vector<Contact> ex_contacts;
  ex_contacts.push_back(contactA_);
  struct NatDetectionData nd_data1 = {contactA_, contact_strC_, node_c,
      &response, done1, NULL, ex_contacts};
  serviceC_->SendNatDetection(nd_data1);
  EXPECT_FALSE(response.IsInitialized());
  // Send request to node B (which has node C's details in his routing table)
  // with node A as newcomer - should succeed.
  response.Clear();
  Callback cb_obj2(&response);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj2, &Callback::CallbackSendNatDet);
  struct NatDetectionData nd_data2 = {contactA_, contact_strB_, node_c,
      &response, done2, NULL, ex_contacts};
  serviceB_->SendNatDetection(nd_data2);
  while (!response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_EQ(kRpcResultSuccess, response.result());
  Contact contactback;
  EXPECT_TRUE(routingtableB_->GetContact(node_idA_, &contactback));
}

TEST_F(NatDetectionTest, BEH_KAD_BootstrapNatDetRv) {
  NatDetectionResponse *nd_response = new NatDetectionResponse;
  Contact node_c;
  BootstrapResponse response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  std::vector<Contact> ex_contacts;
  ex_contacts.push_back(contactA_);
  struct NatDetectionData nd_data1 = {contactA_, contact_strB_, node_c,
      &response, done1, NULL, ex_contacts};
  serviceB_->Bootstrap_NatDetectionRv(nd_response, nd_data1);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  // It should be able to contact another node
  EXPECT_EQ(1, response.nat_type());

  response.Clear();
  nd_response = new NatDetectionResponse;
  nd_response->set_result(kRpcResultFailure);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  struct NatDetectionData nd_data2 = {contactA_, contact_strB_, node_c,
      &response, done2, NULL, ex_contacts};
  serviceB_->Bootstrap_NatDetectionRv(nd_response, nd_data2);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_EQ(3, response.nat_type());
  Contact contactback;
  EXPECT_TRUE(routingtableB_->GetContact(node_idA_, &contactback));
  routingtableB_->RemoveContact(node_idA_, false);
  EXPECT_FALSE(routingtableB_->GetContact(node_idA_, &contactback));

  nd_response = new NatDetectionResponse;
  response.Clear();
  nd_response->set_result(kRpcResultSuccess);
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  struct NatDetectionData nd_data3 = {contactA_, contact_strB_, node_c,
      &response, done3, NULL, ex_contacts};
  serviceB_->Bootstrap_NatDetectionRv(nd_response, nd_data3);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_EQ(2, response.nat_type());
  EXPECT_TRUE(routingtableB_->GetContact(node_idA_, &contactback));
}

TEST_F(NatDetectionTest, FUNC_KAD_CompleteBootstrapNatDet) {
  // If NatDetectionResponse is uninitialised, NAT type can't be asserted by
  // node C, as his routing table is empty
  NatDetectionResponse *nd_response = new NatDetectionResponse;
  Contact node_c;
  BootstrapResponse response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  std::vector<Contact> ex_contacts;
  rpcprotocol::Controller *ctrl1 = new rpcprotocol::Controller;
  struct NatDetectionData nd_data1 = {contactA_, contact_strC_, node_c,
      &response, done1, ctrl1, ex_contacts};
  serviceC_->Bootstrap_NatDetection(nd_response, nd_data1);
  EXPECT_EQ("", response.result());
  EXPECT_EQ(0, response.nat_type());
  Contact contactback;
  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));

//   If NatDetectionResponse is uninitialised, NAT type can't be asserted, so
//   node B calls new NatDetection rpc and should identify NAT type as 1.
  nd_response = new NatDetectionResponse;
  response.Clear();
  rpcprotocol::Controller *ctrl2 = new rpcprotocol::Controller;
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  struct NatDetectionData nd_data2 = {contactA_, contact_strB_, node_c,
      &response, done2, ctrl2, ex_contacts};
  serviceB_->Bootstrap_NatDetection(nd_response, nd_data2);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));

  EXPECT_EQ(1, response.nat_type());
  EXPECT_TRUE(routingtableB_->GetContact(node_idA_, &contactback));
  routingtableB_->RemoveContact(node_idA_, false);
  EXPECT_FALSE(routingtableB_->GetContact(node_idA_, &contactback));

  // If NatDetectionResponse is failure, NAT type can't be asserted, so node B
  // calls new NatDetection rpc and should identify NAT type as 1.
  nd_response = new NatDetectionResponse;
  response.Clear();
  nd_response->set_result(kRpcResultFailure);
  rpcprotocol::Controller *ctrl3 = new rpcprotocol::Controller;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  struct NatDetectionData nd_data3 = {contactA_, contact_strB_, node_c,
      &response, done3, ctrl3, ex_contacts};
  serviceB_->Bootstrap_NatDetection(nd_response, nd_data3);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_EQ(1, response.nat_type());
  EXPECT_TRUE(routingtableB_->GetContact(node_idA_, &contactback));
  routingtableB_->RemoveContact(node_idA_, false);
  EXPECT_FALSE(routingtableB_->GetContact(node_idA_, &contactback));

  // If NatDetectionResponse is success, NAT type is 1.
  nd_response = new NatDetectionResponse;
  response.Clear();
  nd_response->set_result(kRpcResultSuccess);
  rpcprotocol::Controller *ctrl4 = new rpcprotocol::Controller;
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  struct NatDetectionData nd_data4 = {contactA_, contact_strB_, node_c,
      &response, done4, ctrl4, ex_contacts};
  serviceB_->Bootstrap_NatDetection(nd_response, nd_data4);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_EQ(1, response.nat_type());
  EXPECT_TRUE(routingtableB_->GetContact(node_idA_, &contactback));
  routingtableB_->RemoveContact(node_idA_, false);
  EXPECT_FALSE(routingtableB_->GetContact(node_idA_, &contactback));

  // If NatDetectionResponse is failure, NAT type can't be asserted, so node B
  // calls new NatDetection rpc.  If node C is switched off, this should fail.
  ex_contacts.push_back(contactA_);
  nd_response = new NatDetectionResponse;
  response.Clear();
  nd_response->set_result(kRpcResultFailure);
  rpcprotocol::Controller *ctrl5 = new rpcprotocol::Controller;
  google::protobuf::Closure *done5 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  struct NatDetectionData nd_data5 = {contactA_, contact_strB_, contactC_,
      &response, done5, ctrl5, ex_contacts};
  knodeimpl3_->Leave();
  ASSERT_FALSE(knodeimpl3_->is_joined());
  serviceB_->Bootstrap_NatDetection(nd_response, nd_data5);
  while (!response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
  EXPECT_EQ(kad::kRpcResultFailure, response.result());
  EXPECT_FALSE(routingtableB_->GetContact(node_idA_, &contactback));
  channel_managerB_->StopTransport();
}

TEST_F(NatDetectionTest, BEH_KAD_CompleteNatDet) {
  // With request uninitialised, fail.
  NatDetectionRequest nd_request;
  NatDetectionResponse nd_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  rpcprotocol::Controller controller1;
  serviceC_->NatDetection(&controller1, &nd_request, &nd_response, done1);
  while (!nd_response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_TRUE(nd_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, nd_response.result());
  Contact contactback;
  EXPECT_FALSE(routingtableA_->GetContact(node_idC_, &contactback));
  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));

  // With request incorrectly initialised, fail.
  nd_request.set_newcomer(contact_strA_);
  nd_request.set_bootstrap_node(contact_strB_);
  nd_request.set_type(11);
  nd_request.set_sender_id(node_idA_);
  nd_response.Clear();
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  rpcprotocol::Controller controller2;
  serviceC_->NatDetection(&controller2, &nd_request, &nd_response, done2);
  while (!nd_response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_TRUE(nd_response.IsInitialized());
  EXPECT_EQ(kRpcResultFailure, nd_response.result());
  EXPECT_FALSE(routingtableA_->GetContact(node_idC_, &contactback));
  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));

  // With request type == 1, node C tries to ping node A.
  nd_request.set_newcomer(contact_strA_);
  nd_request.set_bootstrap_node(contact_strB_);
  nd_request.set_type(1);
  nd_request.set_sender_id(node_idA_);
  nd_response.Clear();
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  rpcprotocol::Controller controller3;
  serviceC_->NatDetection(&controller3, &nd_request, &nd_response, done3);
  while (!nd_response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_TRUE(nd_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, nd_response.result());
  EXPECT_TRUE(routingtableA_->GetContact(node_idC_, &contactback));
  // Node C hasn't added A's details as there weren't enough to warrant addition
  // at the nat detection ping stage.
  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));
  routingtableA_->RemoveContact(node_idC_, false);
  EXPECT_FALSE(routingtableA_->GetContact(node_idC_, &contactback));

  // With request type == 2, node C tries to rendezvouz with node A via node B.
  nd_request.set_newcomer(contact_strA_);
  nd_request.set_bootstrap_node(contact_strB_);
  nd_request.set_type(2);
  nd_request.set_sender_id(node_idA_);
  nd_response.Clear();
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  rpcprotocol::Controller controller4;
  serviceC_->NatDetection(&controller4, &nd_request, &nd_response, done4);
  while (!nd_response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_TRUE(nd_response.IsInitialized());
  EXPECT_EQ(kRpcResultSuccess, nd_response.result());
  EXPECT_TRUE(routingtableA_->GetContact(node_idC_, &contactback));
  // Node C hasn't added A's details as there weren't enough to warrant addition
  // at the nat detection ping stage.
  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));
}

TEST_F(NatDetectionTest, BEH_KAD_FullBootstrap) {
  // With request uninitialised, fail.
  BootstrapRequest request;
  BootstrapResponse response;
  Callback cb_obj;
//  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
//      (&cb_obj, &Callback::CallbackFunction);
//  rpcprotocol::Controller controller1;
//  serviceB_->Bootstrap(&controller1, &request, &response, done1);
//  while (!response.IsInitialized())
//    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//  EXPECT_EQ(kad::kRpcResultFailure, response.result());
//  Contact contactback;
//  EXPECT_FALSE(routingtableA_->GetContact(node_idC_, &contactback));
//  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));

  // Check for id == client_node_id
  request.set_newcomer_id(client_node_id());
  request.set_newcomer_local_ip(knodeimpl1_->local_host_ip());
  request.set_newcomer_local_port(knodeimpl1_->local_host_port());
  request.set_newcomer_ext_ip(knodeimpl1_->host_ip());
  request.set_newcomer_ext_port(knodeimpl1_->host_port());
//  response.Clear();
//  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
//      (&cb_obj, &Callback::CallbackFunction);
//  rpcprotocol::Controller controller2;
//  serviceB_->Bootstrap(&controller2, &request, &response, done2);
//  while (!response.IsInitialized())
//    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//  EXPECT_EQ(kRpcResultSuccess, response.result());
//  EXPECT_EQ(node_idB_, response.bootstrap_id());
//  EXPECT_EQ(knodeimpl1_->host_ip(), response.newcomer_ext_ip());
//  EXPECT_EQ(knodeimpl1_->host_port(), response.newcomer_ext_port());
//  EXPECT_FALSE(routingtableA_->GetContact(node_idC_, &contactback));
//  EXPECT_FALSE(routingtableC_->GetContact(node_idA_, &contactback));

  // Check for normal id
  request.set_newcomer_id(knodeimpl1_->node_id());
  response.Clear();
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  rpcprotocol::Controller controller3;
  serviceB_->Bootstrap(&controller3, &request, &response, done3);
  while (!response.has_nat_type())
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  EXPECT_EQ(kRpcResultSuccess, response.result());
  EXPECT_EQ(node_idB_, response.bootstrap_id());
  EXPECT_EQ(knodeimpl1_->host_ip(), response.newcomer_ext_ip());
  EXPECT_EQ(knodeimpl1_->host_port(), response.newcomer_ext_port());
  EXPECT_EQ(1, response.nat_type());
}

}  // namespace kad
