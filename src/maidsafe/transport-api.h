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

#ifndef MAIDSAFE_TRANSPORT_API_H_
#define MAIDSAFE_TRANSPORT_API_H_

#include <string>
#include "maidsafe/maidsafe-dht_config.h"

#if MAIDSAFE_DHT_VERSION < 12
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

namespace transport {

void CleanUp();

class Transport {
 public:
  Transport();
  int ConnectToSend(const std::string &remote_ip, const uint16_t &remote_port,
      const std::string &local_ip, const uint16_t &local_port,
      const std::string &rendezvous_ip, const uint16_t &rendezvous_port,
      const bool &keep_connection, boost::uint32_t *conn_id);
  int Send(const rpcprotocol::RpcMessage &data, const boost::uint32_t &conn_id,
      const bool &new_skt);
  int Send(const std::string &data, const boost::uint32_t &conn_id,
      const bool &new_skt);
  int Start(const boost::uint16_t &port);
  int StartLocal(const boost::uint16_t &port);
  bool RegisterOnRPCMessage(boost::function<void(const rpcprotocol::RpcMessage&,
      const boost::uint32_t&, const float &)> on_rpcmessage);
  bool RegisterOnMessage(boost::function<void(const std::string&,
      const boost::uint32_t&, const float &)> on_message);
  bool RegisterOnSend(boost::function<void(const boost::uint32_t&,
      const bool&)> on_send);
  bool RegisterOnServerDown(boost::function<void(const bool&,
        const std::string&, const boost::uint16_t&)> on_server_down);
  void CloseConnection(const boost::uint32_t &connection_id);
  void Stop();
  bool is_stopped() const;
  struct sockaddr& peer_address();
  bool GetPeerAddr(const boost::uint32_t &conn_id, struct sockaddr *addr);
  bool ConnectionExists(const boost::uint32_t &connection_id);
  bool HasReceivedData(const boost::uint32_t &connection_id, int64_t *size);
  boost::uint16_t listening_port();
  void StartPingRendezvous(const bool &directly_connected,
      const std::string &my_rendezvous_ip, const boost::uint16_t
      &my_rendezvous_port);
  void StopPingRendezvous();
  bool CanConnect(const std::string &ip, const uint16_t &port);
  bool IsAddrUsable(const std::string &local_ip,
      const std::string &remote_ip, const uint16_t &remote_port);
  bool IsPortAvailable(const boost::uint16_t &port);
 private:
  boost::shared_ptr<TransportImpl> pimpl_;
};
}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_API_H_
