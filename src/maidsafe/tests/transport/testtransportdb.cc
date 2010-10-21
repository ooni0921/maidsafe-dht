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
#include <boost/progress.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>

#include <list>
#include <string>

#include "maidsafe/base/log.h"
#include "maidsafe/base/network_interface.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/transport/transportdb.h"

namespace test_db_transport {

class TransportNode {
 public:
  TransportNode(transport::TransportHandler *tnode_handler,
                boost::int16_t transport_id)
      : tnode_handler_(tnode_handler), transport_id_(transport_id),
        successful_conn_(0), refused_conn_(0) {}
  transport::TransportHandler *tnode_handler() { return tnode_handler_; }
  int successful_conn() { return successful_conn_; }
  int refused_conn() { return refused_conn_; }
  void IncreaseSuccessfulConn() { ++successful_conn_; }
  void IncreaseRefusedConn() { ++refused_conn_; }
  boost::int16_t GetTransID() { return transport_id_; }
 private:
  transport::TransportHandler *tnode_handler_;
  boost::int16_t transport_id_;
  int successful_conn_, refused_conn_;
};

void send_string(TransportNode* node, int port, int repeat,
                 rpcprotocol::RpcMessage msg, bool keep_conn, int our_port) {
  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip;
  if (base::GetLocalAddress(&local_address)) {
    ip = local_address.to_string();
  } else {
    ip = std::string(ip);
  }
  for (int i = 0; i < repeat; ++i) {
    int send_res = node->tnode_handler()->ConnectToSend(ip, port, "", 0, "", 0,
                                                        keep_conn, &id,
                                                        node->GetTransID());
    if (send_res == 1002) {
      // connection refused - wait 10 sec and resend
      boost::this_thread::sleep(boost::posix_time::seconds(10));
      send_res = node->tnode_handler()->ConnectToSend(ip, port, "", 0, "", 0,
                                                      keep_conn, &id,
                                                      node->GetTransID());
    }
    if (send_res == 0) {
      node->tnode_handler()->Send(msg, id, true, node->GetTransID());
      node->IncreaseSuccessfulConn();
    } else {
      node->IncreaseRefusedConn();
      printf("Failed to send\n");
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  std::cout << "thread " << our_port << " finished sending "
            << node->successful_conn() << " messages." << std::endl;
}

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
    ++msgs_received_;
    if (!target_msg_.empty() && message == target_msg_)
      ++msgs_confirmed_;
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
      ++msgs_sent_;
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

class MessageHandlerEchoReq {
 public:
  explicit MessageHandlerEchoReq(transport::TransportHandler *node)
      : node_(node),
        msgs(),
        ids(),
        dead_server_(true),
        server_ip_(),
        server_port_(0),
        msgs_sent_(0) {}
    void OnRPCMessage(const rpcprotocol::RpcMessage &msg,
                      const boost::uint32_t &connection_id,
                      const boost::int16_t transport_id,
                      const float &rtt) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(connection_id);
    struct sockaddr addr;
    if (!node_->GetPeerAddr(connection_id, transport_id, &addr))
      LOG(INFO) << "addr not found" << std::endl;
    std::string peer_ip(inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr));
    boost::uint16_t peer_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
    LOG(INFO) << "message " << msgs.size() << " arrived from " << peer_ip << ":"
              << peer_port << " . RTT = " << rtt << std::endl;
    // replying same msg
    if (msgs.size() < size_t(10))
      node_->Send(msg, connection_id, false, transport_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const std::string &ip,
    const boost::uint16_t &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void OnSend(const boost::uint32_t &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  transport::TransportHandler *node_;
  std::list<std::string> msgs;
  std::list<boost::uint32_t> ids;
  bool dead_server_;
  std::string server_ip_;
  boost::uint16_t server_port_;
  int msgs_sent_;
 private:
  MessageHandlerEchoReq(const MessageHandlerEchoReq&);
  MessageHandlerEchoReq& operator=(const MessageHandlerEchoReq&);
};

class MessageHandlerEchoResp {
 public:
  explicit MessageHandlerEchoResp(transport::TransportHandler *node)
      : node_(node), msgs(), ids(), dead_server_(true),
        server_ip_(), server_port_(0), msgs_sent_(0) {}
    void OnRPCMessage(const rpcprotocol::RpcMessage &msg,
                      const boost::uint32_t &connection_id,
                      const boost::int16_t transport_id,
                      const float &rtt) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(connection_id);
    LOG(INFO) << "message " << msgs.size() << " arrived. RTT = " << rtt
              << std::endl;
    // replying same msg
    node_->CloseConnection(connection_id, transport_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const std::string &ip,
                              const boost::uint16_t &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void OnSend(const boost::uint32_t &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  transport::TransportHandler *node_;
  std::list<std::string> msgs;
  std::list<boost::uint32_t> ids;
  bool dead_server_;
  std::string server_ip_;
  boost::uint16_t server_port_;
  int msgs_sent_;
 private:
  MessageHandlerEchoResp(const MessageHandlerEchoResp&);
  MessageHandlerEchoResp& operator=(const MessageHandlerEchoResp&);
};

class TransportTestDb : public testing::Test {
 protected:
  TransportTestDb() : local_address_() {}
  virtual ~TransportTestDb() {}
  virtual void SetUp() { base::GetLocalAddress(&local_address_); }
  virtual void TearDown() {}
  boost::asio::ip::address local_address_;

 private:
  TransportTestDb(const TransportTestDb&);
  TransportTestDb& operator=(const TransportTestDb&);
};

TEST_F(TransportTestDb, BEH_TRANS_SendOneMessageFromOneToAnother) {
  boost::uint32_t id = 0;
  transport::TransportHandler node1_handler, node2_handler;
  transport::TransportDb node1_trans_db, node2_trans_db;
  boost::int16_t node1_id, node2_id;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler[2];

  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer,
                  &msg_handler[1], _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));

  boost::uint16_t lp_node2(node2_handler.listening_port(node2_id));
  rpcprotocol::RpcMessage msg;
  msg.set_rpc_type(rpcprotocol::REQUEST);
  msg.set_message_id(2000);
  msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  msg.SerializeToString(&sent_msg);
  ASSERT_EQ(-1, node1_handler.Send(msg, id, true, node1_id));
  ASSERT_EQ(-1, node1_handler.Send(msg, id, false, node1_id));
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, false,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  ASSERT_TRUE(msg_handler[0].msgs.empty());
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
  ASSERT_EQ(1, msg_handler[0].msgs_sent_);
}

TEST_F(TransportTestDb, BEH_TRANS_SendMessagesFromManyToOne) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
                              node4_handler;
  boost::int16_t node1_id, node2_id, node3_id, node4_id;
  transport::TransportDb node1_trans_db, node2_trans_db, node3_trans_db,
                         node4_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  node3_handler.Register(&node3_trans_db, &node3_id);
  node4_handler.Register(&node4_trans_db, &node4_id);
  MessageHandler msg_handler[4];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
    boost::bind(&MessageHandler::OnRPCMessage,
                &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
    _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
    &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));

  ASSERT_TRUE(node3_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[2], _1, _2, _3, _4)));
  ASSERT_TRUE(node3_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer,
                  &msg_handler[2], _1, _2, _3)));
  ASSERT_TRUE(node3_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  ASSERT_EQ(0, node3_handler.Start(50002, node3_id));

  ASSERT_TRUE(node4_handler.RegisterOnRPCMessage(
    boost::bind(&MessageHandler::OnRPCMessage,
                &msg_handler[3], _1, _2, _3, _4)));
  ASSERT_TRUE(node4_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer,
                  &msg_handler[3], _1, _2, _3)));
  ASSERT_TRUE(node4_handler.RegisterOnSend(
       boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2)));
  ASSERT_EQ(0, node4_handler.Start(50003, node4_id));

  boost::uint16_t lp_node4 = node4_handler.listening_port(node4_id);
  std::list<std::string> sent_msgs;
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, false,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, false,
                                           &id, node2_id));
  ASSERT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node3_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, false,
                                           &id, node3_id));
  ASSERT_EQ(0, node3_handler.Send(rpc_msg, id, true, node3_id));
  boost::uint32_t now = base::GetEpochTime();
  while (msg_handler[3].msgs.size() < size_t(3) &&
         base::GetEpochTime() - now < 15)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(msg_handler[i].msgs.empty());
    ASSERT_EQ(1, msg_handler[i].msgs_sent_);
  }
  ASSERT_FALSE(msg_handler[3].msgs.empty());
  ASSERT_EQ(msg_handler[3].msgs.size(), size_t(3));
  msg_handler[3].msgs.sort();
  sent_msgs.sort();
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(msg_handler[3].msgs.front(), sent_msgs.front());
    msg_handler[3].msgs.pop_front();
    sent_msgs.pop_front();
  }
}

TEST_F(TransportTestDb, BEH_TRANS_SendMessagesFromManyToMany) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
                              node4_handler, node5_handler, node6_handler;
  transport::TransportDb node1_trans_db, node2_trans_db, node3_trans_db,
                         node4_trans_db, node5_trans_db, node6_trans_db;
  boost::int16_t node1_id, node2_id, node3_id, node4_id, node5_id, node6_id;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  node3_handler.Register(&node3_trans_db, &node3_id);
  node4_handler.Register(&node4_trans_db, &node4_id);
  node5_handler.Register(&node5_trans_db, &node5_id);
  node6_handler.Register(&node6_trans_db, &node6_id);
  MessageHandler msg_handler[6];

  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));

  ASSERT_TRUE(node3_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[2], _1, _2, _3, _4)));
  ASSERT_TRUE(node3_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                  _1, _2, _3)));
  ASSERT_TRUE(node3_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  ASSERT_EQ(0, node3_handler.Start(50002, node3_id));

  ASSERT_TRUE(node4_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[3], _1, _2, _3, _4)));
  ASSERT_TRUE(node4_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                  _1, _2, _3)));
  ASSERT_TRUE(node4_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2)));
  ASSERT_EQ(0, node4_handler.Start(50003, node4_id));
  boost::uint16_t lp_node4 = node4_handler.listening_port(node4_id);

  ASSERT_TRUE(node5_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[4], _1, _2, _3, _4)));
  ASSERT_TRUE(node5_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[4],
                  _1, _2, _3)));
  ASSERT_TRUE(node5_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[4], _1, _2)));
  ASSERT_EQ(0, node5_handler.Start(50004, node5_id));
  boost::uint16_t lp_node5 = node5_handler.listening_port(node5_id);

  ASSERT_TRUE(node6_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[5], _1, _2, _3, _4)));
  ASSERT_TRUE(node6_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[5],
                  _1, _2, _3)));
  ASSERT_TRUE(node6_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[5], _1, _2)));
  ASSERT_EQ(0, node6_handler.Start(50005, node6_id));
  boost::uint16_t lp_node6_handler = node6_handler.listening_port(node6_id);

  std::string sent_msgs[3];
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64*1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[0] = ser_rpc_msg;
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, false,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64*1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[1] = ser_rpc_msg;
  ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node5, "", 0, "", 0, false,
                                           &id, node1_id));
  ASSERT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64*1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[2] = ser_rpc_msg;
  ASSERT_EQ(0, node3_handler.ConnectToSend(ip, lp_node6_handler, "", 0, "", 0,
                                           false, &id, node3_id));
  ASSERT_EQ(0, node3_handler.Send(rpc_msg, id, true, node3_id));
  boost::uint32_t now = base::GetEpochTime();
  bool msgs_received[3] = {false, false, false};
  while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
          base::GetEpochTime() - now < 15) {
    boost::uint16_t zero = 0;
    if (static_cast<boost::uint16_t>(msg_handler[3].msgs.size()) > zero)
      msgs_received[0] = true;
    if (static_cast<boost::uint16_t>(msg_handler[4].msgs.size()) > zero)
      msgs_received[1] = true;
    if (static_cast<boost::uint16_t>(msg_handler[5].msgs.size()) > zero)
      msgs_received[2] = true;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  node5_handler.Stop(node5_id);
  node6_handler.Stop(node6_id);
  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(msg_handler[i].msgs.empty());
    ASSERT_EQ(1, msg_handler[i].msgs_sent_);
  }
  for (int i = 3; i < 6; i++) {
    ASSERT_EQ(size_t(1), msg_handler[i].msgs.size());
    ASSERT_EQ(msg_handler[i].msgs.front(), sent_msgs[i-3]);
  }
}

TEST_F(TransportTestDb, BEH_TRANS_SendMessagesFromOneToMany) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
                              node4_handler;
  boost::int16_t node1_id, node2_id, node3_id, node4_id;
  transport::TransportDb node1_udttrans, node2_trans_db, node3_trans_db,
                         node4_trans_db;
  node1_handler.Register(&node1_udttrans, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  node3_handler.Register(&node3_trans_db, &node3_id);
  node4_handler.Register(&node4_trans_db, &node4_id);
  MessageHandler msg_handler[4];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
    boost::bind(&MessageHandler::OnRPCMessage,
                &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  ASSERT_TRUE(node3_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler[2],
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node3_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                  _1, _2, _3)));
  ASSERT_TRUE(node3_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  ASSERT_EQ(0, node3_handler.Start(50002, node3_id));
  boost::uint16_t lp_node3 = node3_handler.listening_port(node3_id);

  ASSERT_TRUE(node4_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[3], _1, _2, _3, _4)));
  ASSERT_TRUE(node4_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                  _1, _2, _3)));
  ASSERT_TRUE(node4_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2)));
  ASSERT_EQ(0, node4_handler.Start(50003, node4_id));
  boost::uint16_t lp_node4 = node4_handler.listening_port(node4_id);

  std::string sent_msgs[3];
  std::string ip(local_address_.to_string());
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[0] = ser_rpc_msg;
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, false,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[1] = ser_rpc_msg;
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node3, "", 0, "", 0,
                                           false, &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[2] = ser_rpc_msg;
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0,
                                           false, &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));

  boost::uint32_t now = base::GetEpochTime();
  bool msgs_received[3] = {false, false, false};
  while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
          base::GetEpochTime() - now < 10) {
    if (msg_handler[1].msgs.size() >= size_t(1))
      msgs_received[0] = true;
    if (msg_handler[2].msgs.size() >= size_t(1))
      msgs_received[1] = true;
    if (msg_handler[3].msgs.size() >= size_t(1))
      msgs_received[2] = true;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  ASSERT_TRUE(msg_handler[0].msgs.empty()) << msg_handler[0].msgs.size();
  ASSERT_EQ(3, msg_handler[0].msgs_sent_);
  for (int i = 0; i < 3; ++i) {
    ASSERT_EQ(size_t(1), msg_handler[i+1].msgs.size());
    ASSERT_EQ(msg_handler[i+1].msgs.front(), sent_msgs[i]);
  }
}

TEST_F(TransportTestDb, BEH_TRANS_TimeoutForSendingToAWrongPeer) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler;
  boost::int16_t node1_id;
  transport::TransportDb node1_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  MessageHandler msg_handler[1];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ip(local_address_.to_string());
  ASSERT_EQ(-1, node1_handler.ConnectToSend(ip, 22222, "", 0, "", 0,
                                            false, &id, node1_id));
  ASSERT_EQ(-1, node1_handler.Send(rpc_msg, id, true, node1_id));
  node1_handler.Stop(node1_id);
}

TEST_F(TransportTestDb, FUNC_TRANS_Send1000Msgs) {
  const int kNumNodes(6), kRepeatSend(200);
  // No. of times to repeat the send message.
  ASSERT_LT(2, kNumNodes);  // ensure enough nodes for test
  EXPECT_LT(1, kRepeatSend);  // ensure enough repeats to make test worthwhile
  MessageHandler msg_handler[kNumNodes];
  transport::TransportHandler* nodes[kNumNodes];
  boost::int16_t transport_ids[kNumNodes];
  transport::TransportDb udt_transports[kNumNodes];
  boost::uint16_t ports[kNumNodes];
  TransportNode* tnodes[kNumNodes-1];
  boost::thread_group thr_grp;
  boost::thread *thrd;
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  transport::TransportHandler *trans_handler;
  for (int i = 0; i < kNumNodes; ++i) {
    trans_handler = new transport::TransportHandler;
    trans_handler->Register(&udt_transports[i], &transport_ids[i]);
    nodes[i] = trans_handler;
    msg_handler[i].keep_msgs_ = false;
    msg_handler[i].target_msg_ = sent_msg;
    msg_handler[i].node_handler_ = nodes[i];
    ASSERT_TRUE(nodes[i]->RegisterOnRPCMessage(
        boost::bind(&MessageHandler::OnRPCMessage,
                    &msg_handler[i], _1, _2, _3, _4)));
    ASSERT_TRUE(nodes[i]->RegisterOnSend(
        boost::bind(&MessageHandler::OnSend,
                    &msg_handler[i], _1, _2)));
    ASSERT_TRUE(nodes[i]->RegisterOnServerDown(
        boost::bind(&MessageHandler::OnDeadRendezvousServer,
                    &msg_handler[i], _1, _2, _3)));

    ASSERT_EQ(0, nodes[i]->Start(50000 + i, transport_ids[i]));
    ports[i] = nodes[i]->listening_port(transport_ids[i]);
    if (i != 0) {
      TransportNode *tnode = new TransportNode(nodes[i], transport_ids[i]);
      thrd = new boost::thread(&send_string, tnode, ports[0], kRepeatSend,
                               rpc_msg, false, ports[i]);
      thr_grp.add_thread(thrd);
      tnodes[i-1] = tnode;
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    } else {
      msg_handler[i].set_node(nodes[i]);
    }
  }

  thr_grp.join_all();
  printf("Done sending.\n");
  int messages_size = 0;
  for (int i = 0; i < kNumNodes - 1; i++) {
    messages_size += tnodes[i]->successful_conn();
  }

  bool finished = false;
  boost::progress_timer t;
  while (!finished && t.elapsed() < 20) {
    if (msg_handler[0].msgs_received_ >= messages_size) {
      finished = true;
      continue;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }

  for (int k = 0; k < kNumNodes; ++k)
    nodes[k]->Stop(transport_ids[k]);
  LOG(INFO) << "Total of successful connections = " << messages_size
            << std::endl;
  ASSERT_EQ(0, msg_handler[0].msgs.size());
  ASSERT_EQ(messages_size, msg_handler[0].msgs_received_);
  ASSERT_EQ(messages_size, msg_handler[0].msgs_confirmed_);
  for (int k = 0; k < kNumNodes; ++k) {
    if (k < kNumNodes - 1)
      delete tnodes[k];
    delete nodes[k];
  }
}

/*
TEST_F(TransportTestDb, BEH_TRANS_GetRemotePeerAddress) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler[2];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));
  boost::uint16_t lp_node1_handler = node1_handler.listening_port(node1_id);

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0,
                                           false, &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  struct sockaddr peer_addr;
  ASSERT_TRUE(node2_handler.peer_address(node1_id, &peer_addr));
  boost::asio::ip::address addr =
      base::NetworkInterface::SockaddrToAddress(&peer_addr);
  ASSERT_EQ(std::string(ip), addr.to_string());

  boost::uint16_t peer_port =
    ntohs(((struct sockaddr_in*)&peer_addr)->sin_port);
  ASSERT_EQ(lp_node1_handler, peer_port);
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}
*/

TEST_F(TransportTestDb, BEH_TRANS_SendMessageFromOneToAnotherBidirectional) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler[2];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
    boost::bind(&MessageHandler::OnRPCMessage,
                &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, true,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  // replying on same channel
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_FALSE(msg_handler[1].ids.empty());
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string reply_msg;
  rpc_msg.SerializeToString(&reply_msg);
  ASSERT_EQ(0, node2_handler.Send(rpc_msg, msg_handler[1].ids.front(), false,
                                  node2_id));
  while (msg_handler[0].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  // Closing the connection
  node1_handler.CloseConnection(msg_handler[0].ids.front(), node1_id);
  node2_handler.CloseConnection(msg_handler[1].ids.front(), node2_id);
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  ASSERT_FALSE(msg_handler[0].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
  ASSERT_EQ(reply_msg, msg_handler[0].msgs.front());
  ASSERT_EQ(1, msg_handler[0].msgs_sent_);
  ASSERT_EQ(1, msg_handler[1].msgs_sent_);
}

TEST_F(TransportTestDb, BEH_TRANS_SendMsgsFromManyToOneBidirectional) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
                              node4_handler;
  transport::TransportDb node1_trans_db, node2_trans_db, node3_trans_db,
                         node4_trans_db;
  boost::int16_t node1_id, node2_id, node3_id, node4_id;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  node3_handler.Register(&node3_trans_db, &node3_id);
  node4_handler.Register(&node4_trans_db, &node4_id);
  MessageHandler msg_handler[4];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));

  ASSERT_TRUE(node3_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[2], _1, _2, _3, _4)));
  ASSERT_TRUE(node3_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                  _1, _2, _3)));
  ASSERT_TRUE(node3_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  ASSERT_EQ(0, node3_handler.Start(50002, node3_id));

  ASSERT_TRUE(node4_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[3], _1, _2, _3, _4)));
  ASSERT_TRUE(node4_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                  _1, _2, _3)));
  ASSERT_TRUE(node4_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2)));
  ASSERT_EQ(0, node4_handler.Start(50003, node4_id));
  boost::uint16_t lp_node4 = node4_handler.listening_port(node4_id);

  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  std::list<std::string> sent_msgs;
  sent_msgs.push_back(ser_rpc_msg);
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, true,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, true,
                                           &id, node2_id));
  ASSERT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node3_handler.ConnectToSend(ip, lp_node4, "", 0, "", 0, true,
                                           &id, node3_id));
  ASSERT_EQ(0, node3_handler.Send(rpc_msg, id, true, node3_id));
  // waiting for all messages to be delivered
  while (msg_handler[3].msgs.size() != size_t(3))
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  // node4_handler responding to all nodes
  std::list<boost::uint32_t>::iterator it;
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string reply_str;
  rpc_msg.SerializeToString(&reply_str);
  for (it = msg_handler[3].ids.begin(); it != msg_handler[3].ids.end(); it++) {
    ASSERT_EQ(0, node4_handler.Send(rpc_msg, *it, false, node4_id));
  }
  // waiting for all replies to arrive
  while (msg_handler[0].msgs.empty() || msg_handler[1].msgs.empty() ||
         msg_handler[2].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  for (it = msg_handler[0].ids.begin(); it != msg_handler[0].ids.end(); it++)
    node1_handler.CloseConnection(*it, node1_id);
  for (it = msg_handler[1].ids.begin(); it != msg_handler[1].ids.end(); it++)
    node2_handler.CloseConnection(*it, node2_id);
  for (it = msg_handler[2].ids.begin(); it != msg_handler[2].ids.end(); it++)
    node3_handler.CloseConnection(*it, node3_id);
  for (it = msg_handler[3].ids.begin(); it != msg_handler[3].ids.end(); it++)
    node3_handler.CloseConnection(*it, node4_id);

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  for (int i = 0; i < 4; i++) {
    ASSERT_FALSE(msg_handler[i].msgs.empty());
    if (i == 3)
      ASSERT_EQ(3, msg_handler[i].msgs_sent_);
    else
      ASSERT_EQ(1, msg_handler[i].msgs_sent_);
  }
  ASSERT_FALSE(msg_handler[3].msgs.empty());
  ASSERT_EQ(msg_handler[3].msgs.size(), size_t(3));
  msg_handler[3].msgs.sort();
  sent_msgs.sort();
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(msg_handler[3].msgs.front(), sent_msgs.front());
    msg_handler[3].msgs.pop_front();
    sent_msgs.pop_front();
    ASSERT_EQ(size_t(1), msg_handler[i].msgs.size());
    ASSERT_EQ(reply_str, msg_handler[i].msgs.front());
  }
  ASSERT_EQ(3, msg_handler[3].msgs_sent_);
}

/*
TEST_F(TransportTestDb, BEH_TRANS_SendOneMessageCloseAConnection) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler[2];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, true,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  // replying on same channel
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_FALSE(msg_handler[1].ids.empty());
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string reply_msg;
  rpc_msg.SerializeToString(&reply_msg);
  node1_handler.CloseConnection(id, node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(-1, node2_handler.Send(rpc_msg, msg_handler[1].ids.front(), false,
                                   node2_id));
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  // Closing the connection
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  ASSERT_TRUE(msg_handler[0].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
}
*/

TEST_F(TransportTestDb, FUNC_TRANS_StartStopTransport) {
  boost::uint32_t id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler[2];
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[0], _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));
  boost::uint16_t lp_node1_handler = node1_handler.listening_port(node1_id);

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage,
                  &msg_handler[1], _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, false,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
  msg_handler[1].msgs.clear();

  // A message was received by node2_handler, now start and stop it 5 times
  for (int i = 0 ; i < 5; i++) {
    node2_handler.Stop(node2_id);
    ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
        boost::bind(&MessageHandler::OnRPCMessage,
                    &msg_handler[1], _1, _2, _3, _4)));
    ASSERT_TRUE(node2_handler.RegisterOnServerDown(
        boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                    _1, _2, _3)));
    ASSERT_TRUE(node2_handler.RegisterOnSend(
        boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
    ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
    lp_node2 = node2_handler.listening_port(node2_id);

    // Sending another message
    rpc_msg.clear_args();
    rpc_msg.set_args(base::RandomString(256 * 1024));
    rpc_msg.SerializeToString(&sent_msg);
    ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, false,
                                             &id, node1_id));
    ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
    while (msg_handler[1].msgs.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    ASSERT_FALSE(msg_handler[1].msgs.empty());
    ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
    msg_handler[1].msgs.clear();

    rpc_msg.clear_args();
    rpc_msg.set_args(base::RandomString(256 * 1024));
    rpc_msg.SerializeToString(&sent_msg);
    ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node1_handler, "", 0, "", 0,
                                             false, &id, node2_id));
    ASSERT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
    while (msg_handler[0].msgs.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    ASSERT_FALSE(msg_handler[0].msgs.empty());
    ASSERT_EQ(sent_msg, msg_handler[0].msgs.front());
    msg_handler[0].msgs.clear();

    boost::this_thread::sleep(boost::posix_time::seconds(2));
  }

  // Sending another message
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&sent_msg);
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, false,
                                           &id, node2_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTestDb, BEH_TRANS_SendRespond) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandlerEchoReq msg_handler1(&node1_handler);
  MessageHandlerEchoResp msg_handler2(&node2_handler);
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandlerEchoReq::OnRPCMessage, &msg_handler1,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandlerEchoReq::OnSend, &msg_handler1, _1, _2)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandlerEchoReq::OnDeadRendezvousServer,
                  &msg_handler1, _1, _2, _3)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));
  boost::uint16_t lp_node1_handler = node1_handler.listening_port(node1_id);

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandlerEchoResp::OnRPCMessage, &msg_handler2,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandlerEchoResp::OnSend, &msg_handler2, _1, _2)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandlerEchoResp::OnDeadRendezvousServer,
                  &msg_handler2, _1, _2, _3)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));

  std::vector<std::string> msgs;
  boost::uint8_t msgs_sent(12);
  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip(local_address_.to_string());
  for (boost::uint8_t i = 0; i < msgs_sent; ++i) {
    rpcprotocol::RpcMessage rpc_msg;
    rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
    rpc_msg.set_message_id(2000);
    rpc_msg.set_args(base::RandomString(256 * 1024));
    std::string ser_rpc_msg;
    rpc_msg.SerializeToString(&ser_rpc_msg);
    msgs.push_back(ser_rpc_msg);
    ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node1_handler, "", 0, "", 0,
                                             true, &id, node2_id));
    ASSERT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  }

  bool finished(false);
  boost::progress_timer t;
  while (!finished && t.elapsed() < 10) {
    if (msg_handler1.msgs.size() == msgs_sent &&
        msg_handler2.msgs.size() == size_t(9)) {
      finished = true;
      continue;
    }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  ASSERT_EQ(msgs_sent, msg_handler1.msgs.size());
  for (unsigned int i = 0; i < msgs_sent; i++) {
    for (unsigned int j = 0; j < msgs_sent; j++) {
      if (msgs[j] == msg_handler1.msgs.front()) {
        msg_handler1.msgs.pop_front();
        break;
      }
    }
  }
  ASSERT_TRUE(msg_handler1.msgs.empty());
  ASSERT_EQ(size_t(9), msg_handler2.msgs.size());
  for (int i = 0; i < 9; i++) {
    for (unsigned int j = 0; j < msgs_sent; j++) {
      if (msgs[j] == msg_handler2.msgs.front()) {
        msg_handler2.msgs.pop_front();
        break;
      }
    }
  }
  ASSERT_TRUE(msg_handler2.msgs.empty());
}

/*
TEST_F(TransportTestDb, BEH_TRANS_FailStartUsedport) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler1;
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
    boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
    _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
    &msg_handler1, _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));
  boost::uint16_t lp_node1_handler = node1_handler.listening_port(node1_id);
  ASSERT_EQ(1, node2_handler.Start(lp_node1_handler, node2_id));
  node1_handler.Stop(node1_id);
}
*/

TEST_F(TransportTestDb, BEH_TRANS_SendMultipleMsgsSameConnection) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip(local_address_.to_string());
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, true,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, false, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, false, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, false, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();
  ASSERT_EQ(4, msg_handler1.msgs_sent_);

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTestDb, BEH_TRANS_NoNotificationForInvalidMsgs) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));
  boost::uint16_t lp_node1_handler = node1_handler.listening_port(node1_id);

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));

  boost::uint32_t id;
  std::string ip(local_address_.to_string());
  ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node1_handler, "", 0, "", 0,
                                           true, &id, node2_id));
  rpcprotocol::RpcMessage rpc_msg;
  ASSERT_EQ(-1, node2_handler.Send(rpc_msg, id, true, node2_id));
  ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node1_handler, "", 0, "", 0,
                                           true, &id, node2_id));
  ASSERT_EQ(-1, node2_handler.Send("", id, true, node2_id));
  // sending an invalid message
  std::string msg = base::RandomString(50);
  ASSERT_EQ(0, node2_handler.ConnectToSend(ip, lp_node1_handler, "", 0, "", 0,
                                           true, &id, node2_id));
  ASSERT_EQ(0, node2_handler.Send(msg, id, true, node2_id));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  ASSERT_TRUE(msg_handler1.msgs.empty());
  ASSERT_TRUE(msg_handler2.msgs.empty());
}

TEST_F(TransportTestDb, BEH_TRANS_RegisterNotifiers) {
  transport::TransportHandler node1_handler;
  boost::int16_t node1_id;
  transport::TransportDb node1_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  ASSERT_EQ(1, node1_handler.Start(50000, node1_id));
  MessageHandler msg_handler1;
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_EQ(1, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                  _1, _2, _3)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_FALSE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1,
                  _1, _2, _3, _4)));
  ASSERT_FALSE(node1_handler.RegisterOnMessage(
      boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
  ASSERT_FALSE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_FALSE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                  _1, _2, _3)));
  node1_handler.Stop(node1_id);
}

TEST_F(TransportTestDb, FUNC_TRANS_ClearConnections) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportDb node1_trans_db, node2_trans_db;
  node1_handler.Register(&node1_trans_db, &node1_id);
  node2_handler.Register(&node2_trans_db, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_TRUE(node1_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node1_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                  _1, _2, _3)));
  ASSERT_TRUE(node1_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_EQ(0, node1_handler.Start(50000, node1_id));

  ASSERT_TRUE(node2_handler.RegisterOnRPCMessage(
      boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2,
                  _1, _2, _3, _4)));
  ASSERT_TRUE(node2_handler.RegisterOnServerDown(
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                  _1, _2, _3)));
  ASSERT_TRUE(node2_handler.RegisterOnSend(
      boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  ASSERT_EQ(0, node2_handler.Start(50001, node2_id));
  boost::uint16_t lp_node2 = node2_handler.listening_port(node2_id);

  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip(local_address_.to_string());
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, true,
                                           &id, node1_id));
  ASSERT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());

  boost::this_thread::sleep(boost::posix_time::seconds(61));
  ASSERT_EQ(-1, node2_handler.Send(rpc_msg, msg_handler2.ids.front(), false,
                                   node2_id));

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

}  // namespace test_db_transport
