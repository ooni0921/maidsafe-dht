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

#ifndef RPCPROTOCOL_CHANNELIMPL_H_
#define RPCPROTOCOL_CHANNELIMPL_H_

#include <boost/asio.hpp>
#include <memory>
#include <string>
#include "base/routingtable.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "transport/transportapi.h"

namespace rpcprotocol {
const std::string TIMEOUT("timeout");

class ControllerImpl : public google::protobuf::RpcController {
 public:
  ControllerImpl() : timeout_(kRpcTimeout), rtt_(0.0), failure_("") {}
  ~ControllerImpl() {}
  virtual void SetFailed(const std::string &failure) { failure_ = failure; }
  virtual void Reset() {}
  virtual bool Failed() const;
  virtual std::string ErrorText() const {return failure_;}
  virtual void StartCancel() {}
  virtual bool IsCanceled() const {return false;}
  virtual void NotifyOnCancel(google::protobuf::Closure*) {}
  // input is in seconds
  void set_timeout(const int &seconds) {timeout_ = seconds*1000;}
  int timeout() const {return timeout_;}
  // rtt in milliseconds
  void set_rtt(const float &rtt) { rtt_ = rtt; }
  float rtt() const { return rtt_; }
 private:
  int timeout_;
  float rtt_;
  std::string failure_;
};

class ChannelImpl : public google::protobuf::RpcChannel {
 public:
  explicit ChannelImpl(rpcprotocol::ChannelManager *channelmanager);
  ChannelImpl(rpcprotocol::ChannelManager *channelmanager,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rv_ip, const boost::uint16_t &rv_port);
  ~ChannelImpl();
  virtual void CallMethod(const google::protobuf::MethodDescriptor *method,
                          google::protobuf::RpcController *controller,
                          const google::protobuf::Message *request,
                          google::protobuf::Message *response,
                          google::protobuf::Closure *done);
  void SetService(google::protobuf::Service *service);
  void HandleRequest(const RpcMessage &request,
      const boost::uint32_t &connection_id, const float &rtt);
 private:
  void SendResponse(const google::protobuf::Message *response, RpcInfo info);
  std::string GetServiceName(const std::string &full_name);
  boost::shared_ptr<transport::Transport> ptransport_;
  rpcprotocol::ChannelManager *pmanager_;
  google::protobuf::Service *pservice_;
  std::string ip_, rv_ip_;
  boost::uint16_t port_, rv_port_;
  ChannelImpl(const ChannelImpl&);
  ChannelImpl& operator=(const ChannelImpl&);
  boost::uint32_t id_;
};
}  // namespace
#endif  // RPCPROTOCOL_CHANNELIMPL_H_
