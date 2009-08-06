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
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include <google/protobuf/descriptor.h>
#include "base/calllatertimer.h"
#include "maidsafe/maidsafe-dht.h"
#include "protobuf/rpcmessage.pb.h"
#include "rpcprotocol/channelimpl.h"
#include "tests/rpcprotocol/testservices.pb.h"
#include "transport/transportapi.h"

class PingTestService : public tests::PingTest {
 public:
  void Ping(google::protobuf::RpcController *controller,
            const tests::PingRequest *request,
            tests::PingResponse *response,
            google::protobuf::Closure *done) {
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    if (request->IsInitialized()) {
      if (request->ping() == "ping") {
        response->set_result("S");
        response->set_pong("pong");
        printf("Got ping request, returning response.\n");
      } else {
        response->set_result("F");
        response->set_pong("");
      }
    }
    printf("Rtt %f\n", ctrler->rtt());
    done->Run();
  }
};

class TestOpService : public tests::TestOp {
 public:
  void Add(google::protobuf::RpcController *controller,
           const tests::BinaryOpRequest *request,
           tests::BinaryOpResponse *response,
           google::protobuf::Closure *done) {
    if (request->IsInitialized())
      response->set_result(request->first() + request->second());
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    printf("Rtt %f\n", ctrler->rtt());
    done->Run();
  }
  void Multiplyl(google::protobuf::RpcController *controller,
           const tests::BinaryOpRequest *request,
           tests::BinaryOpResponse *response,
           google::protobuf::Closure *done) {
    if (request->IsInitialized())
      response->set_result(request->first() * request->second());
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    printf("Rtt %f\n", ctrler->rtt());
    done->Run();
  }
};

class MirrorTestService : public tests::MirrorTest {
 public:
  void Mirror(google::protobuf::RpcController *controller,
              const tests::StringMirrorRequest *request,
              tests::StringMirrorResponse *response,
              google::protobuf::Closure *done) {
    if (request->IsInitialized()) {
      std::string message(request->message());
      std::string inverted(request->message());
      int index = 0;
      printf("Before reversing the string.\n");
      for (int n = message.length() -1; n > -1 ; n--) {
        inverted[index] = message[n];
        index++;
      }
      printf("Done reversing the string.\n");
      response->set_mirrored_string(inverted);
    }
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    printf("Rtt %f\n", ctrler->rtt());
    if (!request->has_not_pause() || !request->not_pause()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
    }
    done->Run();
  }
};

class ResultHolder {
 public:
  ResultHolder() : ping_res(), op_res(), mirror_res() {
    ping_res.set_result("");
    op_res.set_result(-1);
    mirror_res.set_mirrored_string("-");
  }
  void GetPingRes(const tests::PingResponse *response,
      rpcprotocol::Controller *ctrl) {
    if (ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::CANCELED) {
      printf("Ping RPC canceled by the client\n");
      return;
    }
    printf("Received result -- waiting for 1 second.\n");
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    if (response->IsInitialized()) {
      ping_res.set_result(response->result());
      ping_res.set_pong(response->pong());
    } else {
      ping_res.set_result("F");
    }
    printf("Finished callback func.\n");
  }
  void GetOpResult(const tests::BinaryOpResponse *response,
      rpcprotocol::Controller *ctrl) {
    if (ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::CANCELED) {
      printf("BinaryOperation RPC canceled by the client\n");
      return;
    }
    if (response->IsInitialized()) {
      op_res.set_result(response->result());
    } else {
      op_res.set_result(-2);
    }
  }
  void GetMirrorResult(const tests::StringMirrorResponse *response,
      rpcprotocol::Controller *ctrl) {
    if (ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::CANCELED) {
      printf("Mirror RPC canceled by the client\n");
      return;
    }
    if (response->IsInitialized()) {
      mirror_res.set_mirrored_string(response->mirrored_string());
    } else {
      mirror_res.set_mirrored_string("+");
    }
  }
  void Reset() {
    ping_res.Clear();
    ping_res.set_result("");
    op_res.Clear();
    op_res.set_result(-1);
    mirror_res.Clear();
    mirror_res.set_mirrored_string("-");
  }
  tests::PingResponse ping_res;
  tests::BinaryOpResponse op_res;
  tests::StringMirrorResponse mirror_res;
};

inline void HandleDeadServer(const bool &, const std::string &,
  const boost::uint16_t&) {}

class RpcProtocolTest : public testing::Test {
 protected:
  static void SetUpTestCase() {
    server_chann_manager = new rpcprotocol::ChannelManager;
    client_chann_manager = new rpcprotocol::ChannelManager;
  }
  static void TearDownTestCase() {
    delete client_chann_manager;
    delete server_chann_manager;
    UDT::cleanup();
  }
  virtual void SetUp() {
    server_chann_manager->StartTransport(0,
      boost::bind(&HandleDeadServer, _1, _2, _3));
    server_chann_manager->ptransport()->StartPingRendezvous(true, "", 0);
    client_chann_manager->StartTransport(0,
      boost::bind(&HandleDeadServer, _1, _2, _3));
    client_chann_manager->ptransport()->StartPingRendezvous(true, "", 0);
  }
  virtual void TearDown() {
    client_chann_manager->StopTransport();
    server_chann_manager->StopTransport();
    server_chann_manager->ClearChannels();
    client_chann_manager->ClearChannels();
  }
  static boost::shared_ptr<base::CallLaterTimer> stimer, ctimer;
  static rpcprotocol::ChannelManager *server_chann_manager,
                                     *client_chann_manager;
};

rpcprotocol::ChannelManager* RpcProtocolTest::server_chann_manager = NULL;
rpcprotocol::ChannelManager* RpcProtocolTest::client_chann_manager = NULL;

TEST_F(RpcProtocolTest, BEH_RPC_RegisterAChannel) {
  PingTestService service;
  // creating a channel for the service
  rpcprotocol::Channel service_channel(server_chann_manager);
  service_channel.SetService(&service);
  server_chann_manager->RegisterChannel(service.GetDescriptor()->name(),
      &service_channel);
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel(client_chann_manager, "127.0.0.1",
      server_chann_manager->external_port(), "", 0);
  tests::PingTest::Stub stubservice(&out_channel);
  tests::PingRequest req;
  tests::PingResponse resp;
  req.set_ping("ping");
  req.set_ip("127.0.0.1");
  req.set_port(client_chann_manager->external_port());
  ResultHolder resultholder;
  google::protobuf::Closure *done = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp, &controller);
  stubservice.Ping(&controller, &req, &resp, done);
  while (resultholder.ping_res.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, FUNC_RPC_MultipleChannelsRegistered) {
  PingTestService service1;
  TestOpService service2;
  MirrorTestService service3;
  MirrorTestService service4;

  // creating a channel for the service
  rpcprotocol::Channel service_channel1(server_chann_manager);
  service_channel1.SetService(&service1);
  server_chann_manager->RegisterChannel(service1.GetDescriptor()->name(),
      &service_channel1);
  rpcprotocol::Channel service_channel2(server_chann_manager);
  service_channel2.SetService(&service2);
  server_chann_manager->RegisterChannel(service2.GetDescriptor()->name(),
      &service_channel2);
  rpcprotocol::Channel service_channel3(server_chann_manager);
  service_channel3.SetService(&service3);
  server_chann_manager->RegisterChannel(service3.GetDescriptor()->name(),
      &service_channel3);
  rpcprotocol::Channel service_channel4(server_chann_manager);
  service_channel4.SetService(&service4);
  server_chann_manager->RegisterChannel(service4.GetDescriptor()->name(),
      &service_channel4);

  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel(client_chann_manager, "127.0.0.1",
      server_chann_manager->external_port(), "", 0);
  tests::PingTest::Stub stubservice1(&out_channel);
  tests::PingRequest req1;
  tests::PingResponse resp1;
  req1.set_ping("ping");
  req1.set_ip("127.0.0.1");
  req1.set_port(client_chann_manager->external_port());
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp1, &controller);
  stubservice1.Ping(&controller, &req1, &resp1, done1);
  while (resultholder.ping_res.result() == "") {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  resultholder.Reset();
  controller.Reset();

  tests::TestOp::Stub stubservice2(&out_channel);
  tests::BinaryOpRequest req2;
  tests::BinaryOpResponse resp2;
  req2.set_first(3);
  req2.set_second(2);
  req2.set_ip("127.0.0.1");
  req2.set_port(client_chann_manager->external_port());
  rpcprotocol::Controller controller2;
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::BinaryOpResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetOpResult, &resp2, &controller2);
  controller2.set_timeout(6);
  stubservice2.Add(&controller2, &req2, &resp2, done2);
  while (resultholder.op_res.result() == -1) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  ASSERT_EQ(5, resultholder.op_res.result());
  ASSERT_FALSE(controller2.Failed());
  controller2.Reset();

  std::string test_string(base::RandomString(5 * 1024 * 1024));
  tests::MirrorTest::Stub stubservice3(&out_channel);
  tests::StringMirrorRequest req3;
  tests::StringMirrorResponse resp3;
  req3.set_message(test_string);
  req3.set_ip("127.0.0.1");
  req3.set_port(client_chann_manager->external_port());
  rpcprotocol::Controller controller3;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp3, &controller3);
  controller3.set_timeout(1);
  stubservice3.Mirror(&controller3, &req3, &resp3, done3);
  while (resultholder.mirror_res.mirrored_string() == "-") {
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  if ("+" != resultholder.mirror_res.mirrored_string()) {
    printf("Did not time out.\n");
    RpcProtocolTest::server_chann_manager->ClearCallLaters();
    RpcProtocolTest::client_chann_manager->ClearCallLaters();
    FAIL();
  }
  ASSERT_TRUE(controller3.Failed());
  ASSERT_EQ(rpcprotocol::TIMEOUT, controller3.ErrorText());
  resultholder.Reset();
  controller3.Reset();
  tests::MirrorTest::Stub stubservice4(&out_channel);
  tests::StringMirrorRequest req4;
  tests::StringMirrorResponse resp4;
  test_string.replace(test_string.size()-10, 10, "0123456789");
  req4.set_message(test_string);
  req4.set_ip("127.0.0.1");
  req4.set_port(client_chann_manager->external_port());
  rpcprotocol::Controller controller4;
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp4, &controller4);
  controller4.set_timeout(70);
  stubservice4.Mirror(&controller4, &req4, &resp4, done4);

  while (resultholder.mirror_res.mirrored_string() == "-") {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  if ("+" == resultholder.mirror_res.mirrored_string()) {
    printf("Result of mirror wrong.\n");
    RpcProtocolTest::server_chann_manager->ClearCallLaters();
    RpcProtocolTest::client_chann_manager->ClearCallLaters();
    FAIL();
  }
  ASSERT_EQ("9876543210",
      resultholder.mirror_res.mirrored_string().substr(0, 10));
  ASSERT_FALSE(controller4.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, BEH_RPC_ServerAndClientAtSameTime) {
  TestOpService service1;
  rpcprotocol::Channel service_channel1(server_chann_manager);
  service_channel1.SetService(&service1);
  server_chann_manager->RegisterChannel(service1.GetDescriptor()->name(),
      &service_channel1);
  TestOpService service2;
  rpcprotocol::Channel service_channel2(client_chann_manager);
  service_channel2.SetService(&service2);
  client_chann_manager->RegisterChannel(service2.GetDescriptor()->name(),
      &service_channel2);
  rpcprotocol::Controller controller1;
  controller1.set_timeout(5);
  rpcprotocol::Controller controller2;
  controller2.set_timeout(5);

  rpcprotocol::Channel out_channel1(server_chann_manager, "127.0.0.1",
      client_chann_manager->external_port(), "", 0);
  rpcprotocol::Channel out_channel2(client_chann_manager, "127.0.0.1",
      server_chann_manager->external_port(), "", 0);
  tests::TestOp::Stub stubservice1(&out_channel1);

  tests::BinaryOpRequest req1;
  tests::BinaryOpResponse resp1;
  req1.set_first(3);
  req1.set_second(2);
  req1.set_ip("127.0.0.1");
  req1.set_port(server_chann_manager->external_port());

  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::BinaryOpResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetOpResult, &resp1, &controller1);
  stubservice1.Add(&controller1, &req1, &resp1, done1);
  while (resultholder.op_res.result() == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(5, resultholder.op_res.result());
  ASSERT_FALSE(controller1.Failed());
  resultholder.Reset();

  tests::TestOp::Stub stubservice2(&out_channel2);
  tests::BinaryOpRequest req2;
  tests::BinaryOpResponse resp2;
  req2.set_first(4);
  req2.set_second(4);
  req2.set_ip("127.0.0.1");
  req2.set_port(client_chann_manager->external_port());
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::BinaryOpResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetOpResult, &resp2, &controller2);
  stubservice2.Multiplyl(&controller2, &req2, &resp2, done2);
  while (resultholder.op_res.result() == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(16, resultholder.op_res.result());
  ASSERT_FALSE(controller2.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, BEH_RPC_Timeout) {
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  int timeout = 3;
  controller.set_timeout(timeout);
  rpcprotocol::Channel out_channel(client_chann_manager, "127.0.0.1",
      server_chann_manager->external_port() - 1, "", 0);
  tests::PingTest::Stub stubservice(&out_channel);
  tests::PingRequest req;
  tests::PingResponse resp;
  req.set_ping("ping");
  req.set_ip("127.0.0.1");
  req.set_port(client_chann_manager->external_port());
  ResultHolder resultholder;
  google::protobuf::Closure *done = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp, &controller);
  stubservice.Ping(&controller, &req, &resp, done);
  boost::this_thread::sleep(boost::posix_time::seconds(timeout+1));
  ASSERT_EQ("F", resultholder.ping_res.result());
  ASSERT_FALSE(resultholder.ping_res.has_pong());
  ASSERT_TRUE(controller.Failed());
  ASSERT_EQ(rpcprotocol::TIMEOUT, controller.ErrorText());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, FUNC_RPC_DeletePendingRequest) {
  MirrorTestService mirrorservice;
  rpcprotocol::Channel service_channel(server_chann_manager);
  service_channel.SetService(&mirrorservice);
  server_chann_manager->RegisterChannel(mirrorservice.GetDescriptor()->name(),
      &service_channel);
  // Sending rpc to an existing server, but cancelin it before response arrives
  rpcprotocol::Controller controller;
  controller.set_timeout(10);
  rpcprotocol::Channel out_channel1(client_chann_manager, "127.0.0.1",
      server_chann_manager->external_port(), "", 0);
  std::string test_string(base::RandomString(500 * 1024));
  tests::MirrorTest::Stub stubservice1(&out_channel1);
  tests::StringMirrorRequest req1, req2;
  tests::StringMirrorResponse resp1, resp2;
  req1.set_message(test_string);
  req1.set_ip("127.0.0.1");
  req1.set_port(client_chann_manager->external_port());
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp1, &controller);
  stubservice1.Mirror(&controller, &req1, &resp1, done1);
  ASSERT_TRUE(client_chann_manager->DeletePendingRequest(controller.req_id()));
  boost::this_thread::sleep(boost::posix_time::seconds(11));
  ASSERT_EQ(std::string("-"), resultholder.mirror_res.mirrored_string());
  ASSERT_EQ(rpcprotocol::CANCELED, controller.ErrorText());
  controller.Reset();
  ASSERT_EQ(std::string(""), controller.ErrorText());

  // Sending a request to a non-existent server and cancelling before it
  // times out
  controller.set_timeout(3);
  rpcprotocol::Channel out_channel2(client_chann_manager, "2.2.2.1",
      5555, "", 0);
  req2.set_message(test_string);
  req2.set_ip("2.2.2.1");
  req2.set_port(5555);
  tests::MirrorTest::Stub stubservice2(&out_channel2);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp2, &controller);
  stubservice2.Mirror(&controller, &req2, &resp2, done2);
  ASSERT_TRUE(client_chann_manager->DeletePendingRequest(controller.req_id()));
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  ASSERT_EQ(std::string("-"), resultholder.mirror_res.mirrored_string());
  ASSERT_EQ(rpcprotocol::CANCELED, controller.ErrorText());
  ASSERT_FALSE(client_chann_manager->DeletePendingRequest(1));
}

TEST_F(RpcProtocolTest, BEH_RPC_ResetTimeout) {
  MirrorTestService service;
  // creating a channel for the service
  rpcprotocol::Channel service_channel(server_chann_manager);
  service_channel.SetService(&service);
  server_chann_manager->RegisterChannel(service.GetDescriptor()->name(),
      &service_channel);
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(20);
  rpcprotocol::Channel out_channel(client_chann_manager, "127.0.0.1",
      server_chann_manager->external_port(), "", 0);
  tests::MirrorTest::Stub stubservice(&out_channel);
  tests::StringMirrorRequest req;
  tests::StringMirrorResponse resp;
  req.set_message(base::RandomString(1024 * 1024));
  req.set_ip("127.0.0.1");
  req.set_port(client_chann_manager->external_port());
  req.set_not_pause(true);
  ResultHolder resultholder;
  google::protobuf::Closure *done = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp, &controller);
  stubservice.Mirror(&controller, &req, &resp, done);
  while (resultholder.mirror_res.mirrored_string() == "-") {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  if ("+" == resultholder.mirror_res.mirrored_string()) {
    printf("Result of mirror wrong.\n");
    RpcProtocolTest::server_chann_manager->ClearCallLaters();
    RpcProtocolTest::client_chann_manager->ClearCallLaters();
    FAIL();
  }
  ASSERT_FALSE(controller.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST(RpcControllerTest, BEH_RPC_RpcController) {
  rpcprotocol::Controller controller;
  ASSERT_FALSE(controller.Failed());
  ASSERT_EQ(std::string(""), controller.ErrorText());
  ASSERT_EQ(0, controller.req_id());
  controller.SetFailed(rpcprotocol::TIMEOUT);
  boost::uint32_t id = 1234;
  controller.set_req_id(id);
  ASSERT_EQ(id, controller.req_id());
  ASSERT_TRUE(controller.Failed());
  ASSERT_EQ(rpcprotocol::TIMEOUT, controller.ErrorText());
  controller.StartCancel();
  ASSERT_FALSE(controller.IsCanceled());
  controller.Reset();
  ASSERT_FALSE(controller.Failed());
  ASSERT_EQ(std::string(""), controller.ErrorText());
  ASSERT_EQ(0, controller.req_id());
}
