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

#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>
#include <exception>
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/online.h"
#include "maidsafe/base/network_interface.h"

namespace transport {
TransportHandler::TransportHandler()
    : transports_(), next_id_(0), started_count_(0), rpc_message_notifier_(),
      message_notifier_(), server_down_notifier_(), send_notifier_() {}

TransportHandler::~TransportHandler() {}

bool TransportHandler::Registered(transport::Transport *transport_object) {
  bool found = false;
  std::map< boost::int16_t, transport::Transport* >::iterator it =
      transports_.begin();
  while (it != transports_.end() || found) {
    found = (it->second == transport_object);
    ++it;
  }
  return found;
}

int TransportHandler::Register(transport::Transport *transport_object,
                               boost::int16_t *transport_id) {
  if (Registered(transport_object)) {
    DLOG(ERROR) << "Transport is already registered\n";
    return 1;
  }
  std::pair< std::map< boost::int16_t, transport::Transport* >::iterator, bool >
      ret;

  ret = transports_.insert(std::pair< boost::int16_t, transport::Transport* >
      (next_id_++, transport_object));  // NOLINT Alec

  /* Register callbacks for OnRPCMessage etc */
  transport_object->RegisterOnMessage(boost::bind(&TransportHandler::OnMessage,
      this, _1, _2, _3, _4));
  transport_object->RegisterOnRPCMessage(boost::bind(
      &TransportHandler::OnRPCMessage, this, _1, _2, _3, _4));
  transport_object->RegisterOnSend(boost::bind(&TransportHandler::OnSend, this,
      _1, _2));
  transport_object->RegisterOnServerDown(boost::bind(
      &TransportHandler::OnServerDown, this, _1, _2, _3));

  transport_object->set_transport_id(ret.first->first);
  *transport_id = ret.first->first;  // The id in the map
  return 0;
}

void TransportHandler::Remove(const boost::int16_t &transport_id) {
  transports_.erase(transport_id);
}

Transport* TransportHandler::Get(const boost::int16_t &transport_id) {
  return transports_.find(transport_id)->second;
}

int TransportHandler::Start(const boost::uint16_t &port,
                            const boost::int16_t &transport_id) {
  if ((rpc_message_notifier_.empty() && message_notifier_.empty()) ||
       server_down_notifier_.empty() || send_notifier_.empty()) {
    DLOG(ERROR) << "TransportHandler::Start: Notifiers empty\n";
    return 1;
  }
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "Start: Couldn't find Transport matching ID: " <<
        transport_id << "\n";
    return 1;
  }

  ++started_count_;
  return (*it).second->Start(port);
}

void TransportHandler::Stop(const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "Stop: Couldn't find Transport matching ID: " <<
        transport_id << "\n";
    return;
  }

  --started_count_;
  return (*it).second->Stop();
}

void TransportHandler::StopAll() {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  for (it = transports_.begin(); it != transports_.end(); ++it)
    Stop((*it).first);
}

bool TransportHandler::AllAreStopped() {
  return 0 == started_count_;
}

std::list<boost::int16_t> TransportHandler::GetTransportIDByType(
    TransportType transport_type) {
  std::list<boost::int16_t> result;
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  for (it = transports_.begin(); it != transports_.end(); ++it) {
    if ((*it).second->transport_type() == transport_type &&
          !(*it).second->is_stopped()) {
      result.push_back((*it).first);
    }
  }
  return result;
}

bool TransportHandler::IsRegistered(transport::Transport *transport_object) {
  bool result = false;
  for (size_t i = 0; i < transports_.size(); ++i) {
    if (transports_[i] == transport_object) {
      result = true;
      break;
    }
  }
  return result;
}

bool TransportHandler::IsAddressUsable(const std::string &local_ip,
                                    const std::string &remote_ip,
                                    const boost::uint16_t &remote_port,
                                    const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "IsAddressUsable: Couldn't find Transport matching ID: " <<
        transport_id << "\n";
    return false;
  }

  return (*it).second->IsAddressUsable(local_ip, remote_ip, remote_port);
}

bool TransportHandler::IsPortAvailable(const boost::uint16_t &port,
                                       const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "IsPortAvailable: Couldn't find Transport matching ID: "
      << transport_id << "\n";
    return false;
  }

  return (*it).second->IsPortAvailable(port);
}

bool TransportHandler::RegisterOnMessage(
    boost::function<void(const std::string&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float &)> on_message) {
  if (0 == started_count_) {
    message_notifier_ = on_message;
    return true;
  }
  return false;
}

bool TransportHandler::RegisterOnRPCMessage(
    boost::function<void(const rpcprotocol::RpcMessage&,
                         const boost::uint32_t&,
                         const boost::int16_t&,
                         const float &)> on_rpcmessage) {
  if (0 == started_count_) {
    rpc_message_notifier_ = on_rpcmessage;
    return true;
  }
  return false;
}

bool TransportHandler::RegisterOnSend(
    boost::function<void(const boost::uint32_t&, const bool&)>on_send) {
  if (0 == started_count_) {
    send_notifier_ = on_send;
    return true;
  }
  return false;
}

bool TransportHandler::RegisterOnServerDown(
    boost::function<void(const bool&,
                         const std::string&,
                         const boost::uint16_t&)> on_server_down) {
  if (0 == started_count_) {
    server_down_notifier_ = on_server_down;
    return true;
  }
  return false;
}

int TransportHandler::ConnectToSend(const std::string &remote_ip,
                                    const boost::uint16_t &remote_port,
                                    const std::string &local_ip,
                                    const boost::uint16_t &local_port,
                                    const std::string &rendezvous_ip,
                                    const boost::uint16_t &rendezvous_port,
                                    const bool &keep_connection,
                                    boost::uint32_t *connection_id,
                                    const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "ConnectToSend: Couldn't find Transport matching ID: "
      << transport_id << "\n";
    return 1;
  }

  return (*it).second->ConnectToSend(remote_ip, remote_port, local_ip,
    local_port, rendezvous_ip, rendezvous_port, keep_connection, connection_id);
}

int TransportHandler::Send(const rpcprotocol::RpcMessage &data,
                           const boost::uint32_t &connection_id,
                           const bool &new_socket,
                           const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "SendRPC: Couldn't find Transport matching ID: " <<
        transport_id << "\n";
    return 1;
  }

  return (*it).second->Send(data, connection_id, new_socket);
}

int TransportHandler::Send(const std::string &data,
                           const boost::uint32_t &connection_id,
                           const bool &new_socket,
                           const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return 1;

  return (*it).second->Send(data, connection_id, new_socket);
}

int TransportHandler::StartLocal(const boost::uint16_t &port,
                                 const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
  DLOG(ERROR) << "StartLocal: Couldn't find Transport matching ID: " <<
      transport_id << "\n";
    return 1;
  }

  ++started_count_;
  return (*it).second->StartLocal(port);
}

void TransportHandler::CloseConnection(const boost::uint32_t &connection_id,
                                       const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "CloseConnection: Couldn't find Transport matching ID: "
      << transport_id << "\n";
    return;
  }

  (*it).second->CloseConnection(connection_id);
}

bool TransportHandler::is_stopped(const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return false;

  return (*it).second->is_stopped();
}

bool TransportHandler::peer_address(const boost::int16_t &transport_id,
                                    struct sockaddr *peer_addr) {
  boost::asio::ip::address addr = base::NetworkInterface::SockaddrToAddress(
    peer_addr);
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end()) {
    DLOG(ERROR) << "peer_address: Couldn't find Transport matching ID: " <<
        transport_id << "\n";
    return false;
  }

  return (*it).second->peer_address(peer_addr);
}

bool TransportHandler::GetPeerAddr(const boost::uint32_t &connection_id,
                                   const boost::int16_t &transport_id,
                                   struct sockaddr *peer_address) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return false;

  return (*it).second->GetPeerAddr(connection_id, peer_address);
}

bool TransportHandler::ConnectionExists(const boost::uint32_t &connection_id,
                                        const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return false;

  return (*it).second->ConnectionExists(connection_id);
}

bool TransportHandler::HasReceivedData(const boost::uint32_t &connection_id,
                                       const boost::int16_t &transport_id,
                                       boost::int64_t *size) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return false;

  return (*it).second->HasReceivedData(connection_id, size);
}


boost::uint16_t TransportHandler::listening_port(
    const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return false;

  return (*it).second->listening_port();
}

void TransportHandler::StartPingRendezvous(
    const bool &directly_connected,
    const std::string &my_rendezvous_ip,
    const boost::uint16_t &my_rendezvous_port,
    const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return;

  (*it).second->StartPingRendezvous(directly_connected,
    my_rendezvous_ip, my_rendezvous_port);
}

void TransportHandler::StopPingRendezvous() {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  for (it = transports_.begin(); it != transports_.end(); ++it)
    (*it).second->StopPingRendezvous();
}

bool TransportHandler::CanConnect(const std::string &ip,
                                  const boost::uint16_t &port,
                                  const boost::int16_t &transport_id) {
  std::map< boost::int16_t, transport::Transport* >::iterator it;
  it = transports_.find(transport_id);
  if (it == transports_.end())
    return false;

  return (*it).second->CanConnect(ip, port);
}

void TransportHandler::OnRPCMessage(const rpcprotocol::RpcMessage &request,
                                    const boost::uint32_t &connection_id,
                                    const boost::int16_t &transport_id,
                                    const float &rtt) {
    if (!rpc_message_notifier_.empty())
      rpc_message_notifier_(request, connection_id, transport_id, rtt);
}

void TransportHandler::OnMessage(const std::string &request,
                                 const boost::uint32_t &connection_id,
                                 const boost::int16_t &transport_id,
                                 const float &rtt) {
    if (!message_notifier_.empty())
      message_notifier_(request, connection_id, transport_id, rtt);
}

void TransportHandler::OnServerDown(const bool &dead_server,
                                    const std::string &ip,
                                    const boost::uint16_t &port) {
    if (!server_down_notifier_.empty())
      server_down_notifier_(dead_server, ip, port);
}

void TransportHandler::OnSend(const boost::uint32_t &connection_id,
                              const bool &success) {
    if (!send_notifier_.empty())
      send_notifier_(connection_id, success);
}
}  // namespace transport
