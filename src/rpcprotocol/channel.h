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
 *  Created on: Feb 12, 2009
 *      Author: Jose
 */

#ifndef RPCPROTOCOL_CHANNEL_H_
#define RPCPROTOCOL_CHANNEL_H_

//  #define VERBOSE_DEBUG
//  #define SHOW_MUTEX

#include <boost/asio.hpp>
#include <google/protobuf/service.h>
#include <google/protobuf/message.h>
#include <string>
#include <memory>
#include "protobuf/rpcmessage.pb.h"
#include "transport/transportapi.h"
#include "base/utils.h"
#include "base/routingtable.h"


namespace rpcprotocol {

// RPC timeout
const int kRpcTimeout = 7000;  // 7 seconds
class ChannelManager;

class Controller : public google::protobuf::RpcController {
 public:
  Controller() : remote_ip_(""), remote_port_(0), timeout_(kRpcTimeout) {}
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
  RpcInfo() : ctrl(0), rpc_id(0), connection_id(0) {}
  Controller *ctrl;
  boost::uint32_t rpc_id;
  boost::uint32_t connection_id;
};

class Channel : public google::protobuf::RpcChannel {
 public:
  Channel(boost::shared_ptr<transport::Transport> transport,
        ChannelManager *channelmanager);
  Channel(boost::shared_ptr<transport::Transport> transport,
        ChannelManager *channelmanager, const std::string &ip,
        const boost::uint16_t &port, const bool &local);
  ~Channel();
  virtual void CallMethod(const google::protobuf::MethodDescriptor *method,
                          google::protobuf::RpcController *controller,
                          const google::protobuf::Message *request,
                          google::protobuf::Message *response,
                          google::protobuf::Closure *done);
  inline void SetService(google::protobuf::Service* service) {
    pservice_ = service;
  }

  void HandleRequest(const RpcMessage &request,
      const boost::uint32_t &connection_id);
 private:
  void SendResponse(const google::protobuf::Message *response, RpcInfo info);
  std::string GetServiceName(const std::string &full_name);
  boost::shared_ptr<transport::Transport> ptransport_;
  ChannelManager *pmanager_;
  google::protobuf::Service *pservice_;
  std::string ip_;
  boost::uint16_t port_;
  boost::shared_ptr<base::PDRoutingTableHandler> routingtable_;
  Channel(const Channel&);
  Channel& operator=(const Channel&);
  bool local_;
  boost::mutex mutex;
};
}  // namespace rpcprotocol
#endif  // RPCPROTOCOL_CHANNEL_H_
