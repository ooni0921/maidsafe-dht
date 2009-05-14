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

#ifndef RPCPROTOCOL_CHANNELMANAGER_H_
#define RPCPROTOCOL_CHANNELMANAGER_H_

//  #define VERBOSE_DEBUG
//  #define SHOW_MUTEX

#include <map>
#include <string>
#include <memory>
#include "boost/shared_ptr.hpp"
#include "google/protobuf/service.h"
#include "google/protobuf/message.h"

#include "base/calllatertimer.h"
#include "base/utils.h"
#include "base/routingtable.h"
#include "protobuf/callback_messages.pb.h"
#include "rpcprotocol/channel.h"

namespace rpcprotocol {

const std::string kStartTransportSuccess("T");
const std::string kStartTransportFailure("F");

// RPC timeout
// const int kRpcTimeout = 5000;  // 5 seconds


struct PendingReq {
  PendingReq() : args(0), callback(0), connection_id(0) {}
  google::protobuf::Message* args;
  google::protobuf::Closure* callback;
  boost::uint32_t connection_id;
};

class ProtocolInterface {
 public:
  virtual ~ProtocolInterface() {}
  virtual void MessageArrive(const std::string &message,
      const boost::uint32_t &connection_id)=0;
  virtual void MessageSentResult(boost::uint32_t rpc_id, bool result)=0;
  virtual int StartTransport(boost::uint16_t port,
      boost::function<void(const bool&, const std::string&,
                           const boost::uint16_t&)> notify_dead_server)=0;
  virtual int StopTransport()=0;
};

class ChannelManager : public rpcprotocol::ProtocolInterface {
 public:
  explicit ChannelManager(boost::shared_ptr<base::CallLaterTimer> timer);
  ~ChannelManager();
  void RegisterChannel(const std::string &service_name, Channel* channel);
  void UnRegisterChannel(const std::string &service_name);
  void ClearChannels();
  virtual int StartTransport(boost::uint16_t port,
      boost::function<void(const bool&, const std::string&,
                           const boost::uint16_t&)> notify_dead_server);
  virtual int StopTransport();

  virtual void MessageArrive(const std::string &message,
      const boost::uint32_t &connection_id);
  virtual void MessageSentResult(boost::uint32_t , bool ) {}
  boost::uint32_t CreateNewId();
  void AddPendingRequest(const boost::uint32_t &req_id, PendingReq req);
  void DeleteRequest(const boost::uint32_t &req_id);
  void AddReqToTimer(const boost::uint32_t &req_id, const int &timeout);
  void AddConnectionToReq(const boost::uint32_t &req_id,
      const boost::uint32_t &conn_id);
  inline boost::shared_ptr<transport::Transport> ptransport() {
    return ptransport_;
  }
  boost::uint16_t external_port() const {return external_port_;}
  std::string external_ip() const {return external_ip_;}
  bool CheckConnection(const std::string &ip, const uint16_t &port);
 private:
  void HandleResponse(const RpcMessage &response, const std::string &ip,
      const boost::uint16_t &port);
  void TimerHandler(const boost::uint32_t &req_id);
  boost::shared_ptr<transport::Transport> ptransport_;
  bool is_started;
  boost::shared_ptr<base::CallLaterTimer> ptimer_;
  std::vector< boost::shared_ptr<boost::mutex> > mutex_;
  boost::uint32_t current_request_id_;
  std::map<std::string, Channel*> channels_;
  std::map<boost::uint32_t, PendingReq> pending_req_;
  ChannelManager(const ChannelManager&);
  ChannelManager& operator=(const ChannelManager&);
  boost::uint16_t external_port_;
  std::string external_ip_;
  std::auto_ptr<base::PDRoutingTableHandler> routingtable_;
};
}  // namespace rpcprotocol
#endif  // RPCPROTOCOL_CHANNELMANAGER_H_
