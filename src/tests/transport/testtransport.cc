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

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/progress.hpp>
#include <boost/cstdint.hpp>
#include <gtest/gtest.h>
#include <list>
#include <string>
#include "maidsafe/maidsafe-dht_config.h"
#include "transport/transportapi.h"

class TransportNode {
 public:
  explicit TransportNode(transport::Transport *tnode) : tnode_(tnode),
      successful_conn_(0), refused_conn_(0) {}
  transport::Transport *tnode() { return tnode_; }
  int successful_conn() { return successful_conn_; }
  int refused_conn() { return refused_conn_; }
  void IncreaseSuccessfulConn() { successful_conn_++; }
  void IncreaseRefusedConn() { refused_conn_++; }
 private:
  transport::Transport *tnode_;
  int successful_conn_, refused_conn_;
};

void send_string(TransportNode* node,
                 int port,
                 int repeat,
                 rpcprotocol::RpcMessage msg,
                 bool keep_conn,
                 int our_port) {
  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip;
  if (base::get_local_address(&local_address)) {
    ip = local_address.to_string();
  } else {
    ip = std::string("127.0.0.1");
  }
  for (int i = 0; i < repeat; ++i) {
    int send_res = node->tnode()->ConnectToSend(ip, port, "", 0, &id,
        keep_conn);
    if (send_res == 1002) {
      // connection refused - wait 10 sec and resend
      boost::this_thread::sleep(boost::posix_time::seconds(10));
      send_res = node->tnode()->ConnectToSend(ip, port, "", 0, &id, keep_conn);
    }
    if (send_res == 0) {
      node->tnode()->Send(msg, id, true);
      node->IncreaseSuccessfulConn();
    } else {
      node->IncreaseRefusedConn();
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  printf("thread %i finished sending %i messages\n", our_port,
      node->successful_conn());
}

class MessageHandler {
 public:
  MessageHandler(): msgs(), ids(), dead_server_(true), server_ip_(),
    server_port_(0), node_(NULL), msgs_sent_(0) {}
  void OnMessage(const rpcprotocol::RpcMessage &msg,
      const boost::uint32_t conn_id) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(conn_id);
    printf("message %i arrived\n", msgs.size());
    if (node_ != NULL)
      node_->CloseConnection(conn_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const std::string &ip,
    const boost::uint16_t &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void set_node(transport::Transport *node) {
    node_ = node;
  }
  void OnSend(const boost::uint32_t &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  std::list<std::string> msgs;
  std::list<boost::uint32_t> ids;
  bool dead_server_;
  std::string server_ip_;
  boost::uint16_t server_port_;
  transport::Transport *node_;
  int msgs_sent_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
};

class MessageHandlerEchoReq {
 public:
  explicit MessageHandlerEchoReq(transport::Transport *node)
      : node_(node), msgs(), ids(), dead_server_(true), server_ip_(),
        server_port_(0), msgs_sent_(0) {}
    void OnMessage(const rpcprotocol::RpcMessage &msg,
        const boost::uint32_t conn_id) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(conn_id);
    struct sockaddr addr;
    if (!node_->GetPeerAddr(conn_id, &addr))
      printf("addr not found\n");
    std::string peer_ip(inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr));
    boost::uint16_t peer_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
    printf("sender: %s:%d\n", peer_ip.c_str(), peer_port);
    printf("message %i arrived\n", msgs.size());
    // replying same msg
    if (msgs.size() < 10)
      node_->Send(msg, conn_id, false);
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
  transport::Transport *node_;
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
  explicit MessageHandlerEchoResp(transport::Transport *node)
      : node_(node), msgs(), ids(), dead_server_(true), server_ip_(),
        server_port_(0), msgs_sent_(0) {}
    void OnMessage(const rpcprotocol::RpcMessage &msg,
                   const boost::uint32_t conn_id) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(conn_id);
    printf("message %i arrived\n", msgs.size());
    // replying same msg
    node_->CloseConnection(conn_id);
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
  transport::Transport *node_;
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

class TransportTest: public testing::Test {
 protected:
  virtual ~TransportTest() {
    UDT::cleanup();
  }
};

TEST_F(TransportTest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  boost::uint32_t id = 0;
  transport::Transport node1;
  transport::Transport node2;
  boost::uint16_t lp_node1;
  boost::uint16_t lp_node2;
  MessageHandler msg_handler[2];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  lp_node1 = node1.listening_port();
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  lp_node2 = node2.listening_port();
  rpcprotocol::RpcMessage msg;
  msg.set_rpc_type(rpcprotocol::REQUEST);
  msg.set_message_id(2000);
  msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  msg.SerializeToString(&sent_msg);
  ASSERT_EQ(1, node1.Send(msg, id, true));
  ASSERT_EQ(1, node1.Send(msg, id, false));
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(msg, id, true));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  printf("Stopping nodes.\n");
  node1.Stop();
  node2.Stop();
  ASSERT_TRUE(msg_handler[0].msgs.empty());
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
  ASSERT_EQ(1, msg_handler[0].msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToOne) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  transport::Transport node3;
  transport::Transport node4;
  boost::uint16_t lp_node4;
  MessageHandler msg_handler[4];
  node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2));
  node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2));
  node3.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[2], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2));
  node4.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[3], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2));
  lp_node4 = node4.listening_port();
  std::list<std::string> sent_msgs;
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node2.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, false));
  ASSERT_EQ(0, node2.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node3.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, false));
  ASSERT_EQ(0, node3.Send(rpc_msg, id, true));
  printf("messages sent correctly\n");
  boost::uint32_t now = base::get_epoch_time();
  bool msgs_received = false;
  boost::mutex mutex;
  while (!msgs_received && base::get_epoch_time() - now < 15) {
    {
      boost::mutex::scoped_lock guard(mutex);
      if (msg_handler[3].msgs.size() >= 3)
        msgs_received = true;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1.Stop();
  node2.Stop();
  node3.Stop();
  node4.Stop();
  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(msg_handler[i].msgs.empty());
    ASSERT_EQ(1, msg_handler[i].msgs_sent_);
  }
  ASSERT_FALSE(msg_handler[3].msgs.empty());
  ASSERT_EQ(msg_handler[3].msgs.size(), static_cast<unsigned int>(3));
  msg_handler[3].msgs.sort();
  sent_msgs.sort();
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(msg_handler[3].msgs.front(), sent_msgs.front());
    msg_handler[3].msgs.pop_front();
    sent_msgs.pop_front();
  }
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToMany) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  transport::Transport node3;
  transport::Transport node4;
  transport::Transport node5;
  transport::Transport node6;
  boost::uint16_t lp_node4;
  boost::uint16_t lp_node5;
  boost::uint16_t lp_node6;
  MessageHandler msg_handler[6];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  ASSERT_EQ(0, node3.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[2], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  ASSERT_EQ(0, node4.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[3], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2)));
  lp_node4 = node4.listening_port();
  ASSERT_EQ(0, node5.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[4], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[4],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[4], _1, _2)));
  lp_node5 = node5.listening_port();
  ASSERT_EQ(0, node6.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[5], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[5],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[5], _1, _2)));
  lp_node6 = node6.listening_port();
  std::string sent_msgs[3];
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64*1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[0] = ser_rpc_msg;
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64*1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[1] = ser_rpc_msg;
  ASSERT_EQ(0, node2.ConnectToSend("127.0.0.1", lp_node5, "", 0, &id, false));
  ASSERT_EQ(0, node2.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64*1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[2] = ser_rpc_msg;
  ASSERT_EQ(0, node3.ConnectToSend("127.0.0.1", lp_node6, "", 0, &id, false));
  ASSERT_EQ(0, node3.Send(rpc_msg, id, true));
  boost::uint32_t now = base::get_epoch_time();
  bool msgs_received[3] = {false, false, false};
  boost::mutex mutex1;
  boost::mutex mutex2;
  boost::mutex mutex3;
  while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
          base::get_epoch_time() - now < 15) {
    {
      boost::mutex::scoped_lock guard(mutex1);
      if (msg_handler[3].msgs.size() >= 1)
        msgs_received[0] = true;
    }
    {
      boost::mutex::scoped_lock guard(mutex2);
      if (msg_handler[4].msgs.size() >= 1)
        msgs_received[1] = true;
    }
    {
      boost::mutex::scoped_lock guard(mutex3);
      if (msg_handler[5].msgs.size() >= 1)
        msgs_received[2] = true;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1.Stop();
  node2.Stop();
  node3.Stop();
  node4.Stop();
  node5.Stop();
  node6.Stop();
  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(msg_handler[i].msgs.empty());
    ASSERT_EQ(1, msg_handler[i].msgs_sent_);
  }
  for (int i = 3; i < 6; i++) {
    ASSERT_EQ(static_cast<unsigned int>(1), msg_handler[i].msgs.size());
    ASSERT_EQ(msg_handler[i].msgs.front(), sent_msgs[i-3]);
  }
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromOneToMany) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  transport::Transport node3;
  transport::Transport node4;
  boost::uint16_t lp_node2;
  boost::uint16_t lp_node3;
  boost::uint16_t lp_node4;
  MessageHandler msg_handler[4];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  lp_node2 = node2.listening_port();
  ASSERT_EQ(0, node3.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[2], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  lp_node3 = node3.listening_port();
  ASSERT_EQ(0, node4.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[3], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2)));
  lp_node4 = node4.listening_port();
  std::string sent_msgs[3];
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[0] = ser_rpc_msg;
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[1] = ser_rpc_msg;
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node3, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[2] = ser_rpc_msg;
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));

  boost::uint32_t now = base::get_epoch_time();
  bool msgs_received[3] = {false, false, false};
  boost::mutex mutex1;
  boost::mutex mutex2;
  boost::mutex mutex3;
  while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
          base::get_epoch_time() - now < 15) {
    {
      boost::mutex::scoped_lock guard(mutex1);
      if (msg_handler[1].msgs.size() >= 1)
        msgs_received[0] = true;
    }
    {
      boost::mutex::scoped_lock guard(mutex2);
      if (msg_handler[2].msgs.size() >= 1)
        msgs_received[1] = true;
    }
    {
      boost::mutex::scoped_lock guard(mutex3);
      if (msg_handler[3].msgs.size() >= 1)
        msgs_received[2] = true;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1.Stop();
  node2.Stop();
  node3.Stop();
  node4.Stop();
  ASSERT_TRUE(msg_handler[0].msgs.empty());
  ASSERT_EQ(3, msg_handler[0].msgs_sent_);
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(static_cast<unsigned int>(1), msg_handler[i+1].msgs.size());
    ASSERT_EQ(msg_handler[i+1].msgs.front(), sent_msgs[i]);
  }
}

TEST_F(TransportTest, BEH_TRANS_TimeoutForSendingToAWrongPeer) {
  boost::uint32_t id;
  transport::Transport node1;
  MessageHandler msg_handler[1];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  ASSERT_NE(1, node1.ConnectToSend("127.0.0.1", 52002, "", 0, &id, false));
  ASSERT_EQ(1, node1.Send(rpc_msg, id, true));
  node1.Stop();
}

TEST_F(TransportTest, BEH_TRANS_Send100Msgs) {
  const int kNumNodes = 11;
  const int kRepeatSend = 10;  // No. of times to repeat the send message.
  ASSERT_LT(2, kNumNodes);  // ensure enough nodes for test
  EXPECT_LT(1, kRepeatSend);  // ensure enough repeats to make test worthwhile
  MessageHandler msg_handler[kNumNodes];
  transport::Transport* nodes[kNumNodes];
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
  for (int i = 0; i < kNumNodes; ++i) {
    transport::Transport *trans = new transport::Transport;
    ASSERT_EQ(0, trans->Start(0,
      boost::bind(&MessageHandler::OnMessage, &msg_handler[i], _1, _2),
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[i],
                  _1, _2, _3),
      boost::bind(&MessageHandler::OnSend, &msg_handler[i], _1, _2)));
    ports[i] = trans->listening_port();
    if (i != 0) {
      TransportNode *tnode = new TransportNode(trans);
      thrd = new boost::thread(&send_string, tnode, ports[0], kRepeatSend,
                               rpc_msg, false, ports[i]);
      thr_grp.add_thread(thrd);
      tnodes[i-1] = tnode;
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    } else {
      msg_handler[i].set_node(trans);
    }
    nodes[i] = trans;
  }

  thr_grp.join_all();
  unsigned int messages_size = 0;
  for (int i = 0; i < kNumNodes - 1; i++) {
    messages_size += tnodes[i]->successful_conn();
  }

  bool finished = false;
  boost::progress_timer t;
  while (!finished && t.elapsed() < 20) {
      if (msg_handler[0].msgs.size() >= messages_size) {
        finished = true;
        continue;
      }
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }

  for (int k = 0; k < kNumNodes; ++k)
    nodes[k]->Stop();
  printf("total number of successful connections = %i\n", messages_size);
  ASSERT_EQ(messages_size, msg_handler[0].msgs.size());
  while (!msg_handler[0].msgs.empty()) {
    std::string msg = msg_handler[0].msgs.back();
    EXPECT_EQ(sent_msg, msg);
    msg_handler[0].msgs.pop_back();
  }
  for (int k = 0; k < kNumNodes; ++k) {
    if (k < kNumNodes - 1)
      delete tnodes[k];
    delete nodes[k];
  }
}

TEST_F(TransportTest, BEH_TRANS_GetRemotePeerAddress) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  boost::uint16_t lp_node2;
  MessageHandler msg_handler[2];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  boost::uint16_t lp_node1 = node1.listening_port();
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  lp_node2 = node2.listening_port();
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  struct sockaddr peer_addr = node2.peer_address();
  std::string peer_ip(inet_ntoa(((struct sockaddr_in *)&peer_addr)->sin_addr));
  boost::uint16_t peer_port =
    ntohs(((struct sockaddr_in *)&peer_addr)->sin_port);
  ASSERT_EQ("127.0.0.1", peer_ip);
  ASSERT_EQ(lp_node1, peer_port);
  node1.Stop();
  node2.Stop();
}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageFromOneToAnotherBidirectional) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  MessageHandler msg_handler[2];
  boost::uint16_t lp_node2;
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  lp_node2 = node2.listening_port();
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, true));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // replying on same channel
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_FALSE(msg_handler[1].ids.empty());
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string reply_msg;
  rpc_msg.SerializeToString(&reply_msg);
  ASSERT_EQ(0, node2.Send(rpc_msg, msg_handler[1].ids.front(), false));
  while (msg_handler[0].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // Closing the connection
  node1.CloseConnection(msg_handler[0].ids.front());
  node2.CloseConnection(msg_handler[1].ids.front());
  node1.Stop();
  node2.Stop();
  ASSERT_FALSE(msg_handler[0].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
  ASSERT_EQ(reply_msg, msg_handler[0].msgs.front());
  ASSERT_EQ(1, msg_handler[0].msgs_sent_);
  ASSERT_EQ(1, msg_handler[1].msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToOneBidirectional) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  transport::Transport node3;
  transport::Transport node4;
  MessageHandler msg_handler[4];
  boost::uint16_t lp_node4;
  node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2));
  node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2));
  node3.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[2], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2));
  node4.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[3], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[3], _1, _2));
  lp_node4 = node4.listening_port();
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  std::list<std::string> sent_msgs;
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, true));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node2.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, true));
  ASSERT_EQ(0, node2.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  ASSERT_EQ(0, node3.ConnectToSend("127.0.0.1", lp_node4, "", 0, &id, true));
  ASSERT_EQ(0, node3.Send(rpc_msg, id, true));
  // waiting for all messages to be delivered
  while (msg_handler[3].msgs.size() != 3)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // node4 responding to all nodes
  std::list<boost::uint32_t>::iterator it;
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string reply_str;
  rpc_msg.SerializeToString(&reply_str);
  for (it = msg_handler[3].ids.begin(); it != msg_handler[3].ids.end(); it++) {
    ASSERT_EQ(0, node4.Send(rpc_msg, *it, false));
  }
  // waiting for all replies to arrive
  while (msg_handler[0].msgs.empty() || msg_handler[1].msgs.empty() ||
         msg_handler[2].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  for (it = msg_handler[0].ids.begin(); it != msg_handler[0].ids.end(); it++)
    node1.CloseConnection(*it);
  for (it = msg_handler[1].ids.begin(); it != msg_handler[1].ids.end(); it++)
    node2.CloseConnection(*it);
  for (it = msg_handler[2].ids.begin(); it != msg_handler[2].ids.end(); it++)
    node3.CloseConnection(*it);
  for (it = msg_handler[3].ids.begin(); it != msg_handler[3].ids.end(); it++)
    node3.CloseConnection(*it);

  node1.Stop();
  node2.Stop();
  node3.Stop();
  node4.Stop();
  for (int i = 0; i < 4; i++) {
    ASSERT_FALSE(msg_handler[i].msgs.empty());
    if (i == 3)
      ASSERT_EQ(3, msg_handler[i].msgs_sent_);
    else
      ASSERT_EQ(1, msg_handler[i].msgs_sent_);
  }
  ASSERT_FALSE(msg_handler[3].msgs.empty());
  ASSERT_EQ(msg_handler[3].msgs.size(), static_cast<unsigned int>(3));
  msg_handler[3].msgs.sort();
  sent_msgs.sort();
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(msg_handler[3].msgs.front(), sent_msgs.front());
    msg_handler[3].msgs.pop_front();
    sent_msgs.pop_front();
    ASSERT_EQ(static_cast<unsigned int>(1), msg_handler[i].msgs.size());
    ASSERT_EQ(reply_str, msg_handler[i].msgs.front());
  }
  ASSERT_EQ(3, msg_handler[3].msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageCloseAConnection) {
  boost::uint32_t id;
  transport::Transport node1, node2;
  MessageHandler msg_handler[2];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  boost::uint16_t lp_node2 = node2.listening_port();
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, true));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // replying on same channel
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_FALSE(msg_handler[1].ids.empty());
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string reply_msg;
  rpc_msg.SerializeToString(&reply_msg);
  node1.CloseConnection(id);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(1, node2.Send(rpc_msg, msg_handler[1].ids.front(), false));
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  // Closing the connection
  node1.Stop();
  node2.Stop();
  ASSERT_TRUE(msg_handler[0].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
}

TEST_F(TransportTest, FUNC_TRANS_PingRendezvousServer) {
  transport::Transport node1;
  transport::Transport rendezvous_node;
  MessageHandler msg_handler[2];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, rendezvous_node.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  boost::uint16_t lp_rvn = rendezvous_node.listening_port();
  node1.StartPingRendezvous(false, "127.0.0.1", lp_rvn);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  node1.Stop();
  ASSERT_FALSE(msg_handler[0].dead_server_);
  ASSERT_EQ(std::string(""), msg_handler[0].server_ip_);
  ASSERT_EQ(0, msg_handler[0].server_port_);
  rendezvous_node.Stop();
}

TEST_F(TransportTest, FUNC_TRANS_PingDeadRendezvousServer) {
  transport::Transport node1;
  transport::Transport rendezvous_node;
  MessageHandler msg_handler[2];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, rendezvous_node.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  boost::uint16_t lp_rvn = rendezvous_node.listening_port();
  node1.StartPingRendezvous(false, "127.0.0.1", lp_rvn);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  ASSERT_FALSE(msg_handler[0].dead_server_);
  ASSERT_EQ(std::string(""), msg_handler[0].server_ip_);
  ASSERT_EQ(0, msg_handler[0].server_port_);
  rendezvous_node.Stop();
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  node1.Stop();
  ASSERT_TRUE(msg_handler[0].dead_server_);
  ASSERT_EQ(std::string("127.0.0.1"), msg_handler[0].server_ip_);
  ASSERT_EQ(lp_rvn, msg_handler[0].server_port_);
}

TEST_F(TransportTest, FUNC_TRANS_ReconnectToDifferentServer) {
  transport::Transport node1;
  transport::Transport rendezvous_node1;
  transport::Transport rendezvous_node2;
  MessageHandler msg_handler[3];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  ASSERT_EQ(0, rendezvous_node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  boost::uint16_t lp_rvn1 = rendezvous_node1.listening_port();
  ASSERT_EQ(0, rendezvous_node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[2], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  boost::uint16_t lp_rvn2 = rendezvous_node2.listening_port();
  node1.StartPingRendezvous(false, "127.0.0.1", lp_rvn1);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  ASSERT_FALSE(msg_handler[0].dead_server_);
  ASSERT_EQ(std::string(""), msg_handler[0].server_ip_);
  ASSERT_EQ(0, msg_handler[0].server_port_);
  rendezvous_node1.Stop();
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_TRUE(msg_handler[0].dead_server_);
  ASSERT_EQ(std::string("127.0.0.1"), msg_handler[0].server_ip_);
  ASSERT_EQ(lp_rvn1, msg_handler[0].server_port_);
  node1.StartPingRendezvous(false, "127.0.0.1", lp_rvn2);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  ASSERT_FALSE(msg_handler[0].dead_server_);
  ASSERT_EQ(std::string(""), msg_handler[0].server_ip_);
  ASSERT_EQ(0, msg_handler[0].server_port_);
  node1.Stop();
  rendezvous_node2.Stop();
}

TEST_F(TransportTest, FUNC_TRANS_StartStopTransport) {
  boost::uint32_t id;
  transport::Transport node1;
  transport::Transport node2;
  MessageHandler msg_handler[2];
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[0], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[0], _1, _2)));
  boost::uint16_t lp_node1 = node1.listening_port();
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  boost::uint16_t lp_node2 = node2.listening_port();
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
  msg_handler[1].msgs.clear();
  // A message was received by node2, now start and stop it 5 times
  for (int i = 0 ; i < 5; i++) {
    node2.Stop();
    ASSERT_EQ(0, node2.Start(0,
      boost::bind(&MessageHandler::OnMessage, &msg_handler[1], _1, _2),
      boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
                  _1, _2, _3),
      boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
    lp_node2 = node2.listening_port();
    // Sending another message
    rpc_msg.clear_args();
    rpc_msg.set_args(base::RandomString(256 * 1024));
    rpc_msg.SerializeToString(&sent_msg);
    ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, false));
    ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
    while (msg_handler[1].msgs.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    ASSERT_FALSE(msg_handler[1].msgs.empty());
    ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());
    msg_handler[1].msgs.clear();

    rpc_msg.clear_args();
    rpc_msg.set_args(base::RandomString(256 * 1024));
    rpc_msg.SerializeToString(&sent_msg);
    ASSERT_EQ(0, node2.ConnectToSend("127.0.0.1", lp_node1, "", 0, &id, false));
    ASSERT_EQ(0, node2.Send(rpc_msg, id, true));
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
  ASSERT_EQ(0, node1.ConnectToSend("127.0.0.1", lp_node2, "", 0, &id, false));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler[1].msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler[1].msgs.front());

  node1.Stop();
  node2.Stop();
}

TEST_F(TransportTest, FUNC_TRANS_SendRespond) {
  transport::Transport node1;
  transport::Transport node2;
  MessageHandlerEchoReq msg_handler1(&node1);
  MessageHandlerEchoResp msg_handler2(&node2);
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandlerEchoReq::OnMessage, &msg_handler1, _1, _2),
    boost::bind(&MessageHandlerEchoReq::OnDeadRendezvousServer, &msg_handler1,
                _1, _2, _3),
    boost::bind(&MessageHandlerEchoReq::OnSend, &msg_handler1, _1, _2)));
  boost::uint16_t lp_node1 = node1.listening_port();
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandlerEchoResp::OnMessage, &msg_handler2, _1, _2),
    boost::bind(&MessageHandlerEchoResp::OnDeadRendezvousServer, &msg_handler2,
                _1, _2, _3),
    boost::bind(&MessageHandlerEchoResp::OnSend, &msg_handler2, _1, _2)));
  std::vector<std::string> msgs;
  unsigned int msgs_sent = 12;
  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip;
  if (base::get_local_address(&local_address)) {
    ip = local_address.to_string();
  } else {
    ip = std::string("127.0.0.1");
  }
  for (unsigned int i = 0; i < msgs_sent; i++) {
    rpcprotocol::RpcMessage rpc_msg;
    rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
    rpc_msg.set_message_id(2000);
    rpc_msg.set_args(base::RandomString(256 * 1024));
    std::string ser_rpc_msg;
    rpc_msg.SerializeToString(&ser_rpc_msg);
    msgs.push_back(ser_rpc_msg);
    ASSERT_EQ(0, node2.ConnectToSend(ip, lp_node1, "", 0, &id, true));
    ASSERT_EQ(0, node2.Send(rpc_msg, id, true));
  }
  bool finished = false;
  boost::progress_timer t;
  while (!finished && t.elapsed() < 10) {
      if (msg_handler1.msgs.size() == msgs_sent &&
          msg_handler2.msgs.size() == 9) {
        finished = true;
        continue;
      }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  node1.Stop();
  node2.Stop();
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
  ASSERT_EQ(static_cast<unsigned int>(9), msg_handler2.msgs.size());
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

TEST_F(TransportTest, BEH_TRANS_FailStartUsedport) {
  transport::Transport node1;
  transport::Transport node2;
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  boost::uint16_t lp_node1 = node1.listening_port();
  ASSERT_EQ(1, node2.Start(lp_node1,
    boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  node1.Stop();
}

TEST_F(TransportTest, BEH_TRANS_SendMultipleMsgsSameConnection) {
  transport::Transport node1;
  transport::Transport node2;
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  boost::uint16_t lp_node2 = node2.listening_port();
  boost::uint32_t id;
  boost::asio::ip::address local_address;
  std::string ip;
  if (base::get_local_address(&local_address)) {
    ip = local_address.to_string();
  } else {
    ip = std::string("127.0.0.1");
  }
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1.ConnectToSend(ip, lp_node2, "", 0, &id, true));
  ASSERT_EQ(0, node1.Send(rpc_msg, id, true));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1.Send(rpc_msg, id, false));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1.Send(rpc_msg, id, false));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  ASSERT_EQ(0, node1.Send(rpc_msg, id, false));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_FALSE(msg_handler2.msgs.empty());
  ASSERT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();
  ASSERT_EQ(4, msg_handler1.msgs_sent_);

  node1.Stop();
  node2.Stop();
}

TEST_F(TransportTest, BEH_TRANS_SendViaRdz) {
  transport::Transport node1, node2, node3;
  MessageHandler msg_handler1, msg_handler2, msg_handler3;
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  boost::uint16_t lp_node1 = node1.listening_port();
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  ASSERT_EQ(0, node3.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler3, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler3,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler3, _1, _2)));
  boost::uint16_t lp_node3 = node3.listening_port();
  node1.StartPingRendezvous(false, "127.0.0.1", lp_node3);
  rpcprotocol::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  boost::uint32_t id;
  ASSERT_EQ(0, node2.ConnectToSend("127.0.0.1", lp_node1, "127.0.0.1", lp_node3,
      &id, true));
  ASSERT_EQ(0, node2.Send(rpc_msg, id, true));
  while (msg_handler1.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1.Stop();
  node2.Stop();
  node3.Stop();
  ASSERT_FALSE(msg_handler1.msgs.empty());
  ASSERT_EQ(sent_msg, msg_handler1.msgs.front());
  ASSERT_EQ(1, msg_handler2.msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_NoNotificationForInvalidMsgs) {
  transport::Transport node1, node2;
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  boost::uint16_t lp_node1 = node1.listening_port();
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  boost::uint32_t id;
  ASSERT_EQ(0, node2.ConnectToSend("127.0.0.1", lp_node1, "", 0, &id, true));
  ASSERT_EQ(0, node2.Send(base::RandomString(1024*10),
      transport::Transport::STRING, id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  node1.Stop();
  node2.Stop();
  ASSERT_EQ(1, msg_handler2.msgs_sent_);
  ASSERT_TRUE(msg_handler1.msgs.empty());
  ASSERT_TRUE(msg_handler2.msgs.empty());
}

TEST_F(TransportTest, BEH_TRANS_CheckConnection) {
  transport::Transport node1, node2;
  MessageHandler msg_handler1, msg_handler2;
  ASSERT_EQ(0, node1.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler1, _1, _2)));
  ASSERT_EQ(0, node2.Start(0,
    boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2),
    boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
                _1, _2, _3),
    boost::bind(&MessageHandler::OnSend, &msg_handler2, _1, _2)));
  boost::uint16_t lp_node2 = node2.listening_port();
  std::vector<std::string> local_ips = base::get_local_addresses();
  if (local_ips.size() > 0) {
    std::string server_addr = "127.0.0.1";
    for (boost::uint32_t i = 0; i < local_ips.size(); i++) {
      printf("checking local address %s connecting to address %s\n",
        local_ips[i].c_str(), server_addr.c_str());
      ASSERT_FALSE(node1.CheckConnection(local_ips[i], server_addr, lp_node2));
    }
    ASSERT_TRUE(node1.CheckConnection(local_ips[0], local_ips[0], lp_node2));
  } else {
    printf("no local addresses where retrieved\n");
  }
  node1.Stop();
  node2.Stop();
}
