/*
Copyright (c) 2009 maidsafe.net lmited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 *  Created on: Feb 12, 2009
 *      Author: Jose
 */

#ifndef RPCPROTOCOL_CHANNEL_H_
#define RPCPROTOCOL_CHANNEL_H_

#include <boost/asio.hpp>
#include <google/protobuf/service.h>
#include <google/protobuf/message.h>
#include <string>
#include <memory>
#include "protobuf/rpcmessage.pb.h"
#include "transport/transportapi.h"
#include "base/utils.h"
#include "base/routingtable.h"

using boost::asio::ip::udp;
namespace rpcprotocol {

// RPC timeout
const int kRpcTimeout = 7000;  // 5 seconds
class ChannelManager;

class Controller : public google::protobuf::RpcController {
 public:
  Controller() : remote_ip_(""), remote_port_(), timeout_(kRpcTimeout) {}
  ~Controller() {}
  virtual void SetFailed(const std::string&) {}
  virtual void Reset() {}
  virtual bool Failed() const {return false;}
  virtual std::string ErrorText() const {return "";}
  virtual void StartCancel() {}
  virtual bool IsCanceled() const {return false;}
  virtual void NotifyOnCancel(google::protobuf::Closure*) {}
  void set_remote_ip(const std::string &ip) {
    // To send we need ip in decimal dotted format
    if (ip.size() == 4)
      remote_ip_ = base::inet_btoa(ip);
    else
      remote_ip_ = ip;
  }
  void set_remote_port(const uint16_t &port) {remote_port_ = port;}
  std::string remote_ip() const {return remote_ip_;}
  uint16_t remote_port() const {return remote_port_;}
  // input is in seconds
  void set_timeout(const int timeout) {timeout_ = timeout*1000;}
  int timeout() const {return timeout_;}
 private:
  std::string remote_ip_;
  uint16_t remote_port_;
  int timeout_;
};

struct RpcInfo {
  RpcInfo() : ctrl(NULL), rpc_id(), connection_id() {}
  Controller *ctrl;
  boost::uint32_t rpc_id;
  boost::uint32_t connection_id;
};

class Channel : public google::protobuf::RpcChannel {
 public:
  Channel(transport::Transport *transport,
        ChannelManager *channelmanager);
  Channel(transport::Transport *transport,
        ChannelManager *channelmanager, const std::string &ip,
        const boost::uint16_t &port, const bool &local);
  ~Channel();
  virtual void CallMethod(const google::protobuf::MethodDescriptor *method,
                          google::protobuf::RpcController *controller,
                          const google::protobuf::Message *request,
                          google::protobuf::Message *response,
                          google::protobuf::Closure *done);
  void SetService(google::protobuf::Service *service);
  void HandleRequest(const RpcMessage &request,
      const boost::uint32_t &connection_id);
 private:
  void SendResponse(const google::protobuf::Message *response, RpcInfo info);
  std::string GetServiceName(const std::string &full_name);
  transport::Transport *ptransport_;
  ChannelManager *pmanager_;
  google::protobuf::Service *pservice_;
  std::string ip_;
  boost::uint16_t port_;
  boost::shared_ptr<base::PDRoutingTableHandler> routingtable_;
  Channel(const Channel&);
  Channel& operator=(const Channel&);
  bool local_;
};
}  // namespace
#endif  // RPCPROTOCOL_CHANNEL_H_
