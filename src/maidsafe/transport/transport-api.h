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
 * NOTE: This API is unlikely to have any breaking changes applied.  However,  *
 *       it should not be regarded as a final API until this notice is removed.*
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_API_H_

#include <boost/function.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <string>

#if MAIDSAFE_DHT_VERSION < 24
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace rpcprotocol {
class RpcMessage;
}  // namespace rpcprotocol


namespace transport {

class Transport {
 public:
  virtual ~Transport() {}
  virtual TransportType transport_type() = 0;
  virtual boost::int16_t transport_id() = 0;
  virtual void set_transport_id(const boost::int16_t &id) = 0;
  virtual int ConnectToSend(const std::string &remote_ip,
                            const boost::uint16_t &remote_port,
                            const std::string &local_ip,
                            const boost::uint16_t &local_port,
                            const std::string &rendezvous_ip,
                            const boost::uint16_t &rendezvous_port,
                            const bool &keep_connection,
                            boost::uint32_t *connection_id) = 0;
  virtual int Send(const rpcprotocol::RpcMessage &data,
                   const boost::uint32_t &connection_id,
                   const bool &new_socket) = 0;
  virtual int Send(const std::string &data,
                   const boost::uint32_t &connection_id,
                   const bool &new_socket) = 0;
  virtual int Start(const boost::uint16_t &port) = 0;
  virtual int StartLocal(const boost::uint16_t &port) = 0;
  virtual bool RegisterOnRPCMessage(
      boost::function<void(const rpcprotocol::RpcMessage&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float&)> on_rpcmessage) = 0;
  virtual bool RegisterOnMessage(
      boost::function<void(const std::string&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float&)> on_message) = 0;
  virtual bool RegisterOnSend(
      boost::function<void(const boost::uint32_t&, const bool&)> on_send) = 0;
  virtual bool RegisterOnServerDown(
      boost::function <void(const bool&,
                            const std::string&,
                            const boost::uint16_t&)> on_server_down) = 0;
  virtual void CloseConnection(const boost::uint32_t &connection_id) = 0;
  virtual void Stop() = 0;
  virtual bool is_stopped() const = 0;
  virtual bool peer_address(struct sockaddr *peer_addr) = 0;
  virtual bool GetPeerAddr(const boost::uint32_t &connection_id,
                           struct sockaddr *peer_address) = 0;
  virtual bool ConnectionExists(const boost::uint32_t &connection_id) = 0;
  virtual bool HasReceivedData(const boost::uint32_t &connection_id,
                               boost::int64_t *size) = 0;
  virtual boost::uint16_t listening_port() = 0;
  virtual void StartPingRendezvous(
      const bool &directly_connected, const std::string &my_rendezvous_ip,
      const boost::uint16_t &my_rendezvous_port) = 0;
  virtual void StopPingRendezvous() = 0;
  virtual bool CanConnect(const std::string &ip,
                          const boost::uint16_t &port) = 0;
  virtual bool IsAddressUsable(const std::string &local_ip,
                               const std::string &remote_ip,
                               const boost::uint16_t &remote_port) = 0;
  virtual bool IsPortAvailable(const boost::uint16_t &port) = 0;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
