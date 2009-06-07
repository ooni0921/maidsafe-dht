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

// This test shuts down N random nodes at random times and restarts them
// a random amount of seconds later. There is a timer for safety purposes to
// stop the test if one of them fails to restart, but it should otherwise stop
// when all nodes selected have been shut down and restarted.

const int kNetworkSize = 20;
const int kTestK = 4;
const int initialNodePort = 62000;
const unsigned int N = 10;

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


class FunctionalKNodeTest: public testing::Test {
 protected:
  FunctionalKNodeTest() {}
  virtual ~FunctionalKNodeTest() {}
 private:
  FunctionalKNodeTest(const FunctionalKNodeTest&);
  FunctionalKNodeTest &operator=(const FunctionalKNodeTest&);
};

TEST_F(FunctionalKNodeTest, FUNC_KAD_StartStopRandomNodes) {

  // Variable declaration
  std::string kad_config_file("");
  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> >
      channel_managers_;
  std::vector< boost::shared_ptr<kad::KNode> > knodes_;
  std::vector<std::string> dbs_;
  crypto::Crypto cry_obj_;
  GeneralKadCallback cb_;
  std::vector<std::string> node_ids;

  // Deleting & creating directories
  try {
    if (fs::exists("FunctionalKnodeTest"))
      fs::remove_all("FunctionalKnodeTest");
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  fs::create_directories("FunctionalKnodeTest");
  // setup the nodes without starting them
  for (int  i = 0; i < kNetworkSize; ++i) {
    boost::shared_ptr<rpcprotocol::ChannelManager>
        channel_manager_local_(new rpcprotocol::ChannelManager());
    channel_managers_.push_back(channel_manager_local_);

    std::string db_local_ = "FunctionalKnodeTest/datastore" +
                            base::itos(initialNodePort+i);
    dbs_.push_back(db_local_);

    boost::shared_ptr<kad::KNode> knode_local_(new kad::KNode(dbs_[i],
                                               channel_managers_[i],
                                               kad::VAULT,
                                               kTestK,
                                               kad::kAlpha,
                                               kad::kBeta));
    EXPECT_EQ(0, channel_managers_[i]->StartTransport(initialNodePort+i,
              boost::bind(&kad::KNode::HandleDeadRendezvousServer,
              knode_local_.get(), _1, _2, _3)));
    knodes_.push_back(knode_local_);
    cb_.Reset();
  }

  // Start node 0 and add his details to .kadconfig protobuf
  kad_config_file = dbs_[0] + "/.kadconfig";
  knodes_[0]->Join("", kad_config_file,
                   boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1),
                   false);
  wait_result(&cb_);
  ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
  ASSERT_TRUE(knodes_[0]->is_joined());
  printf("Node 0 joined.\n");
  base::KadConfig kad_config;
  base::KadConfig::Contact *kad_contact_ = kad_config.add_contact();
  std::string hex_id;
  base::encode_to_hex(knodes_[0]->node_id(), hex_id);
  kad_contact_->set_node_id(hex_id);
  kad_contact_->set_ip(knodes_[0]->host_ip());
  kad_contact_->set_port(knodes_[0]->host_port());
  kad_contact_->set_local_ip(knodes_[0]->local_host_ip());
  kad_contact_->set_local_port(knodes_[0]->local_host_port());
  std::string node0_id = knodes_[0]->node_id();
  kad_config_file = dbs_[0] + "/.kadconfig";
  std::fstream output1(kad_config_file.c_str(),
                       std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config.SerializeToOstream(&output1));
  output1.close();

  // Copy the .kadconfig to all nodes to have them bootstrap off node 0
  for (int i = 1; i < kNetworkSize; i++) {
    std::string kad_config_file_i = dbs_[i] + "/.kadconfig";
    boost::filesystem::copy_file(kad_config_file, kad_config_file_i);
    ASSERT_TRUE(boost::filesystem::exists(kad_config_file_i));
  }

  // Start the rest of the nodes (1-19)
  for (int  i = 1; i < kNetworkSize; ++i) {
    std::string id("");
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

  // Done with set up of nodes
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

  // Nodes to use for testing
  unsigned int n = 0;
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::Integer rand_num(rng, 32);
  boost::uint32_t num;

  // Generate set of N nodes to be started and stopped
  std::set<int> nodes;
  std::set<int>::iterator it;
  while (nodes.size() < N) {
    if (!rand_num.IsConvertableToLong()) {
      num = std::numeric_limits<uint32_t>::max() + static_cast<uint32_t>(
        rand_num.AbsoluteValue().ConvertToLong());
    } else {
      num = static_cast<uint32_t>(rand_num.AbsoluteValue().ConvertToLong());
    }
    int r_node = 1 + static_cast<int>(num % 19);
    nodes.insert(r_node);
    rand_num.Randomize(rng, 32);
  }

  // Generate times to start and stop
  boost::uint64_t stop_times[N];
  boost::uint64_t restart_times[N];
  boost::uint64_t largest_time = 4;

  for (n = 0; n < N; ++n) {
    if (!rand_num.IsConvertableToLong()) {
      num = std::numeric_limits<uint32_t>::max() + static_cast<uint32_t>(
        rand_num.AbsoluteValue().ConvertToLong());
    } else {
      num = static_cast<uint32_t>(rand_num.AbsoluteValue().ConvertToLong());
    }
    rand_num.Randomize(rng, 32);
    stop_times[n] = 5 + static_cast<boost::uint64_t>(num % 100);
    restart_times[n] = 1;
    while (stop_times[n] >= restart_times[n]) {
      if (!rand_num.IsConvertableToLong()) {
        num = std::numeric_limits<uint32_t>::max() +
          static_cast<uint32_t>(rand_num.AbsoluteValue().ConvertToLong());
      } else {
        num = static_cast<uint32_t>(rand_num.AbsoluteValue().ConvertToLong());
      }
      rand_num.Randomize(rng, 32);
      restart_times[n] = 5 + static_cast<boost::uint64_t>(num % 100);
    }
    restart_times[n] += 5;
    if (restart_times[n] > largest_time) {
      largest_time = restart_times[n];
    }
  }

  // Printing the schedule
  n = 0;
  printf("\n\n\nSchedule:\nNode\tStop Time\tRestart Time\n");
  for (it = nodes.begin(); it != nodes.end(); ++it) {
    printf("%i\t%llu\t\t%llu\n", *it, stop_times[n], restart_times[n]);
    n++;
  }
  printf("\n\n\n");

  // Adding execution to call later timer
  n = 0;
  base::CallLaterTimer clt;
  for (it = nodes.begin(); it != nodes.end(); ++it) {
    cb_.Reset();
    std::string db_local_ = "KnodeTest/datastore" +
                            base::itos(initialNodePort + 1 + *it);
    std::string kad_config_file = db_local_ + "/.kadconfig";
    clt.AddCallLater(stop_times[n] * 1000,
                     boost::bind(&kad::KNode::Leave, knodes_[*it].get()));
    base::callback_func_type f = boost::bind(&GeneralKadCallback::CallbackFunc,
                                             &cb_,
                                             _1);
    clt.AddCallLater(restart_times[n] * 1000,
                     boost::bind(&kad::KNode::Join,
                                 knodes_[*it].get(),
                                 knodes_[*it]->node_id(),
                                 kad_config_file,
                                 f,
                                 false)
                    );
    n++;
  }

  boost::progress_timer t;
  printf("Largest time: %llu\n", largest_time);

  int finished_count = 0;
  std::set<int> stopped_nodes;
  while ((t.elapsed() < largest_time + 10) && (finished_count != N)) {
    for (it = nodes.begin(); it != nodes.end(); ++it) {
      if (!knodes_[*it]->is_joined()) {
        stopped_nodes.insert(*it);
        printf("Node %d has been shut down.\n", *it);
        nodes.erase(*it);
      }
    }
    printf("Stopped nodes size: %d\n", finished_count);
    std::set<int>::iterator it_sn;
    for (it_sn = stopped_nodes.begin(); it_sn != stopped_nodes.end(); ++it_sn) {
      if (knodes_[*it_sn]->is_joined()) {
        finished_count++;
        printf("Node %d has re-joined (count=%d).\n", *it_sn, finished_count);
        stopped_nodes.erase(*it_sn);
      }
    }
    boost::this_thread::sleep(boost::posix_time::seconds(2));
    printf("elapsed: %f\t\tcount %d\n", t.elapsed(), finished_count);
  }

  EXPECT_EQ(N, finished_count) << "One of the nodes(" << N << " vs. " <<
      finished_count << ") did not complete it's cycle";
  for (it = nodes.begin(); it != nodes.end(); ++it) {
    ASSERT_TRUE(knodes_[*it]->is_joined()) <<
      "Node " << *it << " did not rejoin";
  }
  stopped_nodes.clear();
  nodes.clear();

  // Cleaning up after the test
  boost::this_thread::sleep(boost::posix_time::seconds(10));
#ifdef WIN32
  SetConsoleTextAttribute(hconsole, 7 | 0 << 4);
#endif
  printf("In tear down.\n");
  for (int i = kNetworkSize-1; i >= 0; i--) {
    printf("stopping node %i\n", i);
    cb_.Reset();
    knodes_[i]->Leave();
    EXPECT_FALSE(knodes_[i]->is_joined());
    channel_managers_[i]->StopTransport();
    knodes_[i].reset();
    channel_managers_[i].reset();
  }
  try {
    if (fs::exists("FunctionalKnodeTest"))
      fs::remove_all("FunctionalKnodeTest");
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  printf("Finished tear down.\n");

  // This should be moved to the destructor of the test if another test
  // is added to this file.
  UDT::cleanup();
}



