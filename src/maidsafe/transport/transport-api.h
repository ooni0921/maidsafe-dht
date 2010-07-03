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
#include <boost/cstdint.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/signals2/signal.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <string>

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace rpcprotocol {
class RpcMessage;
}  // namespace rpcprotocol


namespace transport {

// return types for sending data
  enum TransportCondition {
  kSucess            = 0,
  kRemoteUnreachable = 1,
  kNoConnection      = 2,
  kNoNetwork         = 3,
  kInvalidIP         = 4,
  kInvalidPort       = 5,
  kInvalidData       = 6,
  kNoSocket          = 7,
  kInvalidAddress    = 8,
  kNoRendezvous      = 9,
  kNoResources       = 10,
  kError             = 11
  };

// Default Types, if you want more you will need to comment this out and
// recreate the enums to suit your needs.
  enum DataType {
    kString      = 0,
    kFile        = 1,
    kPing        = 2,
    kProxyPing   = 3,
    kRPC         = 4
  };

// Rendezvous for nat traversal
// kKClosest is a kademlia implementation issue (you may or not want)
  enum ConnectionType {
    kRendezvous  = 1,
    kKClosest    = 2
  };


/*
Protocol implementation (use Google protobufs for serialisation)
_______________________________________________________________
Type   |
(enum) |
_______________________________________________________________
*/
// This is a partially implmented base clase which is inherited by
// the different transports such as UDT / TCP etc.
class Transport {
public:
  virtual ~Transport() {}
  virtual TransportCondition Ping(const std::string &remote_ip,
                                  const boost::uint16_t &remote_port);
  virtual TransportCondition Send(const std::string &data,
                                  const std::string &remote_ip,
                                  const boost::uint16_t &remote_port) = 0;
  virtual TransportCondition Send(const std::string &data,
                                  const std::string &remote_ip,
                                  const boost::uint16_t &remote_port,
                                  const std::string &rendezvous_ip,
                                  const boost::uint16_t &rendezvous_port) = 0;
  virtual TransportCondition SendFile(const boost::filesystem::path &path,
                                  const std::string &remote_ip,
                                  const boost::uint16_t &remote_port);
  virtual TransportCondition SendFile(const boost::filesystem::path &path,
                                  const std::string &remote_ip,
                                  const boost::uint16_t &remote_port,
                                  const std::string &rendezvous_ip,
                                  const boost::uint16_t &rendezvous_port);                                
  virtual TransportCondition StartListening(const boost::uint16_t &port,
                                            const std::string &ip) = 0;
  virtual void CloseConnection(const boost::uint32_t &connection_id) = 0;
  virtual void StopListening() = 0;
  virtual void KeepConnectionAlive(const std::string &remote_ip,
                                  const boost::uint16_t &remote_port,
                                  const boost::uint16_t &refresh_time,
                                  const std::string &id,
                                  ConnectionType &connection_type);
  virtual TransportCondition KillConnection(const std::string &id);
  virtual bool peer_address(struct sockaddr *peer_addr) = 0;
  virtual boost::uint16_t listening_port() = 0;
// accessors
  virtual bool stopped() { return stopped_; }
  virtual bool nat_pnp() { return nat_pnp_; }
  virtual bool GetPeerAddr(const boost::uint32_t &connection_id,
                           struct sockaddr *peer_address) = 0;
  virtual bool upnp() { return upnp_; }
  virtual void set_nat_pnp(bool nat_pnp) { nat_pnp_ = nat_pnp; }
  virtual bool rendezvous() { return rendezvous_; }
  virtual bool local_port_only() { return local_port_only_; }

// mutators
  virtual void set_upnp(bool upnp) { upnp_ = upnp; }
  virtual bool set_rendezvous(const std::string &my_rendezvous_ip,
                              const boost::uint16_t &my_rendezvous_port);
  virtual void set_local_port_only(bool local_port_only)
                                { local_port_only_ = local_port_only; }

// Signals (boost::signals2)
  typedef boost::signals2::signal<void(const std::string&,
                                      const boost::uint32_t&,
                                      const boost::int16_t&)>
                                      SignalMessageReceived;
  typedef boost::signals2::signal<void(ConnectionType,
                                       const std::string&,
                                       const boost::uint16_t)>
                                       SignalConnectionDown;
 // Connections
  boost::signals2::connection connect_message_recieved(const
                                          SignalMessageReceived::slot_type &
                                          SignalMessageReceived){
    return SignalMessageReceived_.connect(SignalMessageReceived);
  }
  boost::signals2::connection connect_connection_down(ConnectionType,
                                           SignalConnectionDown::slot_type &
                                           SignalConnectionDown) {
    return SignalConnectionDown_.connect(SignalConnectionDown);
  }

protected:
  virtual void StartPingRendezvous(const std::string &my_rendezvous_ip,
                                   const boost::uint16_t &my_rendezvous_port);
  virtual void StartPingRendezvous(const bool &directly_connected,
                                   const std::string &my_rendezvous_ip,
                                   const boost::uint16_t &my_rendezvous_port);
  virtual void StopPingRendezvous();
  SignalMessageReceived SignalMessageReceived_;
  SignalConnectionDown SignalConnectionDown_;
  bool upnp_;
  bool nat_pnp_;
  bool rendezvous_;
  bool local_port_only_;
  bool stopped_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
