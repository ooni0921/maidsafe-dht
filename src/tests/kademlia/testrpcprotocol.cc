/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Oct 2, 2008
 *      Author: haiyang

#include "base/utils.h"
#include "kademlia/kademlia.h"
#include <gtest/gtest.h>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "kademlia/rpcprotocol.h"
#include "kademlia/contact.h"
#include "kademlia/fakenode.h"
#include "kademlia/simutransport.h"
#include "base/singleton.h"
#include "base/calllatertimer.h"
#include "protobuf/kad_rpc_messages.pb.h"
#include "protobuf/callback_messages.pb.h"

class NetStartCallback {
 public:
  NetStartCallback(){}
  void CallbackFunc(const std::string &res) {
    result.ParseFromString(res);
  }
  void Reset() {
    result.Clear();
  }
  net::NetStartResult result;
};

class FakePingCallback {
 public:
  FakePingCallback() {}
  void CallbackFunc(const std::string& res) {
    result.ParseFromString(res);
  }
  void Reset() {
    result.Clear();
  }
  kad::PingResponse result;
};

class RpcProtocolTest: public testing::Test {
 protected:
  RpcProtocolTest() {
  }

  virtual ~RpcProtocolTest() {
  }

  virtual void SetUp() {
    mutex = new boost::recursive_mutex();
    timer = new base::CallLaterTimer(mutex);
    base::Singleton<dht::SimuNetwork> network;
    network.instance()->Reset();
    local_node = new kad::FakeNode(&io_service_, timer, mutex);
    NetStartCallback cb;
    local_node->protocol_->StartListening(35001,
        boost::bind(&NetStartCallback::CallbackFunc, &cb, _1));
  }

  virtual void TearDown() {
    local_node->protocol_->StopListening();
    delete local_node;
    delete timer;
    delete mutex;
  }
  kad::FakeNode *local_node;
  boost::asio::io_service io_service_;
  base::CallLaterTimer *timer;
  boost::recursive_mutex *mutex;
};

TEST_F(RpcProtocolTest, BEH_KAD_ValidRpcRequest) {
  kad::FakeNode remote_node(&io_service_, timer, mutex);
  NetStartCallback cb;
  remote_node.protocol_->StartListening(
      35002,
      boost::bind(&NetStartCallback::CallbackFunc,
                  &cb,
                  _1));
  kad::Contact remote_contact(remote_node.node_id(), "127.0.0.1", 35002);
  cb.Reset();
  FakePingCallback cb1;
  local_node->Ping(remote_contact, boost::bind(&FakePingCallback::CallbackFunc,
      &cb1, _1));
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result.result());
  ASSERT_EQ("pong", cb1.result.echo());
  remote_node.protocol_->StopListening();
}

TEST_F(RpcProtocolTest, BEH_KAD_RpcTimeout) {
  kad::Contact remote_contact(base::RandomString(20), "127.0.0.1", 35003);
  FakePingCallback cb;
  local_node->Ping(remote_contact, boost::bind(&FakePingCallback::CallbackFunc,
      &cb, _1));
  base::sleep(kad::kRpcTimeout/1000+1);
  ASSERT_EQ(kad::kRpcResultFailure, cb.result.result());
}

int main(int argc, char **argv){
  testing::InitGoogleTest(&argc, argv);
  RUN_ALL_TESTS();
  return 0;
}
*/
