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

/*******************************************************************************
 * This is the API for maidsafe-dht and is the only program access for         *
 * developers.  The maidsafe-dht_config.h file included is where configuration *
 * may be saved.  You MUST link the maidsafe-dht library.                      *
 *                                                                             *
 * NOTE: These APIs may be amended or deleted in future releases until this    *
 * notice is removed.                                                          *
 ******************************************************************************/

#ifndef MAIDSAFE_CHANNELMANAGER_H_
#define MAIDSAFE_CHANNELMANAGER_H_

#include <string>
#include "maidsafe/maidsafe-dht_config.h"

#if MAIDSAFE_DHT_VERSION < 12
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

// RPC
namespace rpcprotocol {

class RpcMessage;

// Ensure that a one-to-one relationship is maintained between channelmanager &
// knode.
class ChannelManager {
 public:
  ChannelManager();
  ~ChannelManager();
  void RegisterChannel(const std::string &service_name, Channel* channel);
  void UnRegisterChannel(const std::string &service_name);
  void ClearChannels();
  void ClearCallLaters();
  int StartTransport(boost::uint16_t port,
      boost::function<void(const bool&, const std::string&,
                           const boost::uint16_t&)> notify_dead_server);
  int StartLocalTransport(const boost::uint16_t &port);
  int StopTransport();
  void CleanUpTransport();
  void MessageArrive(const RpcMessage &msg,
      const boost::uint32_t &connection_id, const float &rtt);
  boost::uint32_t CreateNewId();
  void AddPendingRequest(const boost::uint32_t &req_id, PendingReq req);
  bool DeletePendingRequest(const boost::uint32_t &req_id);
  void AddReqToTimer(const boost::uint32_t &req_id, const int &timeout);
  boost::shared_ptr<transport::Transport> ptransport();
  boost::uint16_t external_port() const;
  std::string external_ip() const;
  bool CheckConnection(const std::string &ip, const uint16_t &port);
  bool CheckLocalAddress(const std::string &local_ip,
      const std::string &remote_ip, const uint16_t &remote_port);
  void AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &req_id, const int &timeout);
  void AddChannelId(boost::uint32_t *id);
  void RemoveChannelId(const boost::uint32_t &id);
  void OnlineStatusChanged(const bool &online);
  void StartPingServer(const bool &dir_connected, const std::string &server_ip,
    const boost::uint16_t &server_port);
  void StopPingServer();
 private:
  boost::shared_ptr<ChannelManagerImpl> pimpl_;
};
}  // namespace rpcprotocol

#endif  // MAIDSAFE_CHANNELMANAGER_H_
