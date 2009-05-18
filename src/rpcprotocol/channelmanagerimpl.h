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

#ifndef RPCPROTOCOL_CHANNELMANAGERIMPL_H_
#define RPCPROTOCOL_CHANNELMANAGERIMPL_H_

//  #define VERBOSE_DEBUG
//  #define SHOW_MUTEX

#include <map>
#include <string>
#include <memory>
#include "boost/shared_ptr.hpp"
#include "google/protobuf/service.h"
#include "google/protobuf/message.h"

#include "base/calllatertimer.h"
#include "base/routingtable.h"
#include "maidsafe/maidsafe-dht.h"
#include "protobuf/callback_messages.pb.h"
#include "rpcprotocol/channelimpl.h"
#include "transport/transportapi.h"

namespace rpcprotocol {

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
                             const boost::uint32_t &connection_id) = 0;
  virtual void MessageSentResult(boost::uint32_t rpc_id, bool result) = 0;
  virtual int StartTransport(boost::uint16_t port,
      boost::function<void(const bool&, const std::string&,
                           const boost::uint16_t&)> notify_dead_server) = 0;
  virtual int StopTransport() = 0;
};

class ChannelManagerImpl : public rpcprotocol::ProtocolInterface {
 public:
  ChannelManagerImpl();
  ~ChannelManagerImpl();
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
  ChannelManagerImpl(const ChannelManagerImpl&);
  ChannelManagerImpl& operator=(const ChannelManagerImpl&);
  boost::uint16_t external_port_;
  std::string external_ip_;
  std::auto_ptr<base::PDRoutingTableHandler> routingtable_;
};
}  // namespace rpcprotocol
#endif  // RPCPROTOCOL_CHANNELMANAGERIMPL_H_