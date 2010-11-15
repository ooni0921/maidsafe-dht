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

#include <boost/asio/ip/address.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/progress.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include <list>
#include <string>
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/udt/api.h"
#include "maidsafe/base/network_interface.h"


namespace transport {


namespace test_transporthandler {

class MessageHandler {
 public:
  MessageHandler(): msgs(), raw_msgs(), ids(), raw_ids(), dead_server_(true),
                    server_ip_(), server_port_(0), node_handler_(),
                    msgs_sent_(0), msgs_received_(0), msgs_confirmed_(0),
                    target_msg_(), keep_msgs_(true) {}
  void OnRPCMessage(const rpcprotocol::RpcMessage &msg,
                    const boost::uint32_t &connection_id,
                    const boost::int16_t transport_id,
                    const float &rtt) {
    std::string message;
    msg.SerializeToString(&message);
    msgs_received_++;
    if (!target_msg_.empty() && message == target_msg_)
      msgs_confirmed_++;
    if (keep_msgs_) {
      msgs.push_back(message);
      ids.push_back(connection_id);
    }
    LOG(INFO) << "message " << msgs_received_ << " arrived. RTT = " << rtt
        << std::endl;
    if (node_handler_ != NULL)
      node_handler_->CloseConnection(connection_id, transport_id);
  }
  void OnMessage(const std::string &msg, const boost::uint32_t &connection_id,
                 const boost::int16_t &, const float&) {
    raw_msgs.push_back(msg);
    raw_ids.push_back(connection_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const std::string &ip,
                              const boost::uint16_t &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void set_node(transport::TransportHandler *node_handler) {
    node_handler_ = node_handler;
  }
  void OnSend(const boost::uint32_t &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  std::list<std::string> msgs, raw_msgs;
  std::list<boost::uint32_t> ids, raw_ids;
  bool dead_server_;
  std::string server_ip_;
  boost::uint16_t server_port_;
  transport::TransportHandler *node_handler_;
  int msgs_sent_, msgs_received_, msgs_confirmed_;
  std::string target_msg_;
  bool keep_msgs_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
};

class TransportHandlerTest : public::testing::Test {};

// TestCase 1

TEST_F(TransportHandlerTest, BEH_TRANS_Register) {
  TransportHandler th;
  // check return of 1
  TransportUDT tudt/* = new TransportUDT*/;
  boost::int16_t id;
  ASSERT_EQ(0, th.Register(&tudt, &id));
  ASSERT_EQ(0, id);
  ASSERT_EQ(1, th.Register(&tudt, &id));
  // check return of 0
  // delete tudt;
}

// TestCase 2

TEST_F(TransportHandlerTest, BEH_TRANS_GetTransport) {
  TransportHandler GetTransH;
  Transport *transUdt = new TransportUDT;
  bool getrans;
  boost::int16_t transid, transid_nonexist(100);
  ASSERT_EQ(0, GetTransH.Register(transUdt, &transid));
  getrans = (transUdt == GetTransH.Get(transid));
  ASSERT_TRUE(getrans);
  // This check the behaviour for non-exist transport id::
  getrans = (NULL == GetTransH.Get(transid_nonexist));
  ASSERT_TRUE(getrans);
  delete transUdt;
}

// TestCase 3

TEST_F(TransportHandlerTest, BEH_TRANS_IsRegisteredTransport) {
  TransportHandler IsRegH;
  Transport *transUdt1 = new TransportUDT;
  Transport *transUdt2 = new TransportUDT;
  boost::int16_t transid1;
  boost::int16_t transid2(100);
  ASSERT_EQ(0, IsRegH.Register(transUdt1, &transid1));
  ASSERT_TRUE(IsRegH.IsRegistered(transUdt1));
  ASSERT_FALSE(IsRegH.IsRegistered(transUdt2));
  delete transUdt1;
  delete transUdt2;
}

// TestCase 4

TEST_F(TransportHandlerTest, BEH_TRANS_StopTransport) {
  TransportHandler StopH;
  Transport *tStopUdt = new TransportUDT;
  boost::int16_t tStopid, countBeforeStop, tStopid_nonexist(1000);
  ASSERT_EQ(0, StopH.Register(tStopUdt, &tStopid));
  ASSERT_EQ(0, StopH.started_count_);
  StopH.Stop(tStopid);
  ASSERT_EQ(0, StopH.started_count_);
  // Test for non-existing Transport-id
  countBeforeStop = StopH.started_count_;
  StopH.Stop(tStopid_nonexist);
  ASSERT_EQ(countBeforeStop, StopH.started_count_);
  delete tStopUdt;
}

// TestCase 5

TEST_F(TransportHandlerTest, BEH_TRANS_ListeningPortForTransport) {
  TransportHandler lHandler;
  Transport *lTransport = new TransportUDT;
  Transport *lTransport1 = new TransportUDT;
  boost::int16_t lTransportid, lTransportid1, lTransportid2(1000);
  boost::uint16_t lListen_port, lListen_port1, lListen_port2;
  ASSERT_EQ(0, lHandler.Register(lTransport, &lTransportid));
  ASSERT_TRUE(lHandler.listening_port(lTransportid, &lListen_port));
  ASSERT_EQ(0, lHandler.Register(lTransport1, &lTransportid1));
  ASSERT_TRUE(lHandler.listening_port(lTransportid1, &lListen_port1));
  ASSERT_FALSE(lHandler.listening_port(lTransportid2, &lListen_port2));
  delete lTransport;
  delete lTransport1;
}

// TestCase 6

TEST_F(TransportHandlerTest, BEH_TRANS_StartLocalTransport) {
  TransportHandler slHandler;
  Transport *slTransport = new TransportUDT;
  Transport *slTransport1 = new TransportUDT;
  boost::int16_t slTransportid, slTransportid1, slTransportid2(1000);
  ASSERT_EQ(0, slHandler.Register(slTransport, &slTransportid));
  ASSERT_EQ(0, slHandler.StartLocal(0, slTransportid));
  ASSERT_EQ(1, slHandler.started_count_);
  ASSERT_EQ(0, slHandler.Register(slTransport1, &slTransportid1));
  ASSERT_EQ(0, slHandler.StartLocal(0, slTransportid1));
  ASSERT_EQ(2, slHandler.started_count_);
  ASSERT_EQ(1, slHandler.StartLocal(0, slTransportid2));
  ASSERT_EQ(2, slHandler.started_count_);
  slHandler.StopAll();
  delete slTransport;
  delete slTransport1;
}

// TestCase 7

TEST_F(TransportHandlerTest, BEH_TRANS_UnRegisterTransport) {
  TransportHandler unregHandler;
  Transport *unregTransport = new TransportUDT;
  Transport *unregTransport1 = new TransportUDT;
  boost::int16_t unregTransportid, unregTransportid1;
  ASSERT_EQ(0, unregHandler.Register(unregTransport, &unregTransportid));
  ASSERT_EQ(0, unregHandler.Register(unregTransport1, &unregTransportid1));
  unregHandler.UnRegister(unregTransportid);
  ASSERT_FALSE(unregHandler.IsRegistered(unregTransport));
  ASSERT_TRUE(unregHandler.IsRegistered(unregTransport1));
  unregHandler.UnRegister(unregTransportid1);
  ASSERT_FALSE(unregHandler.IsRegistered(unregTransport1));
  delete unregTransport;
  delete unregTransport1;
}

// TestCase 8

TEST_F(TransportHandlerTest, BEH_TRANS_IsStoppedTransport) {
  TransportHandler isHandler;
  Transport *isTransport = new TransportUDT;
  Transport *isTransport1 = new TransportUDT;
  boost::int16_t isTransportid, isTransportid1;
  ASSERT_EQ(0, isHandler.Register(isTransport, &isTransportid));
  ASSERT_EQ(0, isHandler.Register(isTransport1, &isTransportid1));
  ASSERT_EQ(0, isHandler.StartLocal(0, isTransportid));
  ASSERT_EQ(0, isHandler.StartLocal(0, isTransportid1));
  isHandler.Stop(isTransportid);
  ASSERT_TRUE(isHandler.is_stopped(isTransportid));
  ASSERT_FALSE(isHandler.is_stopped(isTransportid1));
  isHandler.Stop(isTransportid1);
  ASSERT_TRUE(isHandler.is_stopped(isTransportid1));
  delete isTransport;
  delete isTransport1;
}

// TestCase 9

TEST_F(TransportHandlerTest, BEH_TRANS_StopAllTransport) {
  TransportHandler slHandler;
  Transport *slTransport = new TransportUDT;
  Transport *slTransport1 = new TransportUDT;
  boost::int16_t slTransportid, slTransportid1;
  ASSERT_EQ(0, slHandler.Register(slTransport, &slTransportid));
  ASSERT_EQ(0, slHandler.StartLocal(0, slTransportid));
  ASSERT_EQ(0, slHandler.Register(slTransport1, &slTransportid1));
  ASSERT_EQ(0, slHandler.StartLocal(0, slTransportid1));
  ASSERT_EQ(2, slHandler.started_count_);
  slHandler.StopAll();
  ASSERT_EQ(0, slHandler.started_count_);
  delete slTransport;
  delete slTransport1;
}

// TestCase 10

TEST_F(TransportHandlerTest, BEH_TRANS_AllAreStoppedTransport) {
  TransportHandler slHandler;
  Transport *slTransport = new TransportUDT;
  Transport *slTransport1 = new TransportUDT;
  boost::int16_t slTransportid, slTransportid1;
  ASSERT_EQ(0, slHandler.Register(slTransport, &slTransportid));
  ASSERT_EQ(0, slHandler.StartLocal(0, slTransportid));
  ASSERT_EQ(0, slHandler.Register(slTransport1, &slTransportid1));
  ASSERT_EQ(0, slHandler.StartLocal(0, slTransportid1));
  ASSERT_FALSE(slHandler.AllAreStopped());
  slHandler.StopAll();
  ASSERT_TRUE(slHandler.AllAreStopped());
  delete slTransport;
  delete slTransport1;
}

// TestCase 11

TEST_F(TransportHandlerTest, BEH_TRANS_StartTransport) {
  TransportHandler sHandler;
  MessageHandler msgHandler;
  Transport *sTransport = new TransportUDT;
  boost::int16_t sTransportid, sTransportid1(1000);
  ASSERT_EQ(0, sHandler.Register(sTransport, &sTransportid));
  ASSERT_EQ(1, sHandler.Start(50000, sTransportid));
  ASSERT_TRUE(sHandler.RegisterOnMessage(
      boost::bind(&MessageHandler::OnMessage,
               &msgHandler, _1, _2, _3, _4)));
  ASSERT_TRUE(sHandler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msgHandler,
              _1, _2, _3)));
  ASSERT_TRUE(sHandler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
      &msgHandler, _1, _2)));
  ASSERT_EQ(0, sHandler.Start(0, sTransportid));
  ASSERT_EQ(1, sHandler.Start(0, sTransportid1));
  sHandler.StopAll();
  delete sTransport;
}

// TestCase 12

TEST_F(TransportHandlerTest, BEH_TRANS_RegisterOnMsgTransport) {
  TransportHandler sHandler;
  MessageHandler msgHandler;
  Transport *sTransport = new TransportUDT;
  boost::int16_t sTransportid, sTransportid1(1000);
  ASSERT_EQ(0, sHandler.Register(sTransport, &sTransportid));
  ASSERT_TRUE(sHandler.RegisterOnMessage(
      boost::bind(&MessageHandler::OnMessage,
              &msgHandler, _1, _2, _3, _4)));
  ASSERT_TRUE(sHandler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msgHandler,
              _1, _2, _3)));
  ASSERT_TRUE(sHandler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
      &msgHandler, _1, _2)));
  ASSERT_EQ(0, sHandler.Start(0, sTransportid));
  ASSERT_FALSE(sHandler.RegisterOnMessage(
      boost::bind(&MessageHandler::OnMessage,
              &msgHandler, _1, _2, _3, _4)));
  sHandler.StopAll();
  delete sTransport;
}

// TestCase 13

TEST_F(TransportHandlerTest, BEH_TRANS_RegisterOnRPCMsgTransport) {
  TransportHandler sHandler;
  MessageHandler msgHandler;
  Transport *sTransport = new TransportUDT;
  boost::int16_t sTransportid, sTransportid1(1000);
  ASSERT_EQ(0, sHandler.Register(sTransport, &sTransportid));
  ASSERT_TRUE(sHandler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
              &msgHandler, _1, _2, _3, _4)));
  ASSERT_TRUE(sHandler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msgHandler,
              _1, _2, _3)));
  ASSERT_TRUE(sHandler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
      &msgHandler, _1, _2)));
  ASSERT_EQ(0, sHandler.Start(0, sTransportid));
  ASSERT_FALSE(sHandler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
              &msgHandler, _1, _2, _3, _4)));
  sHandler.StopAll();
  delete sTransport;
}

// TestCase 14

TEST_F(TransportHandlerTest, BEH_TRANS_RegisterOnSendTransport) {
  TransportHandler sHandler;
  MessageHandler msgHandler;
  Transport *sTransport = new TransportUDT;
  boost::int16_t sTransportid, sTransportid1(1000);
  ASSERT_EQ(0, sHandler.Register(sTransport, &sTransportid));
  ASSERT_TRUE(sHandler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
              &msgHandler, _1, _2, _3, _4)));
  ASSERT_TRUE(sHandler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msgHandler,
              _1, _2, _3)));
  ASSERT_TRUE(sHandler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
      &msgHandler, _1, _2)));
  ASSERT_EQ(0, sHandler.Start(0, sTransportid));
  ASSERT_FALSE(sHandler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend,
              &msgHandler, _1, _2)));
  sHandler.StopAll();
  delete sTransport;
}

// TestCase 15

TEST_F(TransportHandlerTest, BEH_TRANS_RegisterOnServerDownTransport) {
  TransportHandler sHandler;
  MessageHandler msgHandler;
  Transport *sTransport = new TransportUDT;
  boost::int16_t sTransportid, sTransportid1(1000);
  ASSERT_EQ(0, sHandler.Register(sTransport, &sTransportid));
  ASSERT_TRUE(sHandler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
              &msgHandler, _1, _2, _3, _4)));
  ASSERT_TRUE(sHandler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer,
              &msgHandler, _1, _2, _3)));
  ASSERT_TRUE(sHandler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
      &msgHandler, _1, _2)));
  ASSERT_EQ(0, sHandler.Start(0, sTransportid));
  ASSERT_FALSE(sHandler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer,
              &msgHandler, _1, _2, _3)));
  sHandler.StopAll();
  delete sTransport;
}

}  // namespace test_transporthandler

}  // namespace transport
