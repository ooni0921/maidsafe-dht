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

#include "maidsafe/transportudt.h"
#include "transport/transportudtimpl.h"


namespace transport {
TransportUDT::TransportUDT() : pimpl_(new TransportUDTImpl()) {}

TransportUDT::~TransportUDT() {}

Transport::TransportType TransportUDT::GetType() {
  return pimpl_->GetType();
}

boost::int16_t TransportUDT::GetID() {
  return pimpl_->GetID();
}

void TransportUDT::SetID(const boost::int16_t id) {
  pimpl_->SetID(id);
}

void TransportUDT::CleanUp() {
  TransportUDTImpl::CleanUp();
}

int TransportUDT::ConnectToSend(const std::string &remote_ip,
                                const uint16_t &remote_port,
                                const std::string &local_ip,
                                const uint16_t &local_port,
                                const std::string &rendezvous_ip,
                                const uint16_t &rendezvous_port,
                                const bool &keep_connection,
                                boost::uint32_t *conn_id) {
  return pimpl_->ConnectToSend(remote_ip, remote_port, local_ip, local_port,
                               rendezvous_ip, rendezvous_port, keep_connection,
                               conn_id);
}

int TransportUDT::Send(const rpcprotocol::RpcMessage &data,
                       const boost::uint32_t &conn_id,
                       const bool &new_skt) {
  return pimpl_->Send(data, conn_id, new_skt);
}

int TransportUDT::Send(const std::string &data,
                       const boost::uint32_t &conn_id,
                       const bool &new_skt) {
  return pimpl_->Send(data, conn_id, new_skt);
}

int TransportUDT::Start(const boost::uint16_t & port) {
  return pimpl_->Start(port);
}

int TransportUDT::StartLocal(const boost::uint16_t &port) {
  return pimpl_->StartLocal(port);
}

bool TransportUDT::RegisterOnRPCMessage(
    boost::function<void(const rpcprotocol::RpcMessage&,
                         const boost::uint32_t&,
                         const boost::int16_t&,
                         const float &)> on_rpcmessage) {
  return pimpl_->RegisterOnRPCMessage(on_rpcmessage);
}

bool TransportUDT::RegisterOnMessage(
    boost::function<void(const std::string&,
                         const boost::uint32_t&,
                         const boost::int16_t&,
                         const float &)> on_message) {
  return pimpl_->RegisterOnMessage(on_message);
}

bool TransportUDT::RegisterOnSend(
    boost::function<void(const boost::uint32_t&,
                         const bool&)> on_send) {
  return pimpl_->RegisterOnSend(on_send);
}

bool TransportUDT::RegisterOnServerDown(
    boost::function<void(const bool&,
                         const std::string&,
                         const boost::uint16_t&)> on_server_down) {
  return pimpl_->RegisterOnServerDown(on_server_down);
}

void TransportUDT::CloseConnection(const boost::uint32_t &connection_id) {
  pimpl_->CloseConnection(connection_id);
}

void TransportUDT::Stop() {
  pimpl_->Stop();
}

bool TransportUDT::is_stopped() const {
  return pimpl_->is_stopped();
}

struct sockaddr& TransportUDT::peer_address() {
  return pimpl_->peer_address();
}

bool TransportUDT::GetPeerAddr(const boost::uint32_t &conn_id,
                               struct sockaddr *addr) {
  return pimpl_->GetPeerAddr(conn_id, addr);
}

bool TransportUDT::ConnectionExists(const boost::uint32_t &connection_id) {
  return pimpl_->ConnectionExists(connection_id);
}

bool TransportUDT::HasReceivedData(const boost::uint32_t &connection_id,
                                   boost::int64_t *size) {
  return pimpl_->HasReceivedData(connection_id, size);
}

boost::uint16_t TransportUDT::listening_port() {
  return pimpl_->listening_port();
}

void TransportUDT::StartPingRendezvous(const bool &directly_connected,
                                       const std::string &my_rendezvous_ip,
                                       const boost::uint16_t
                                           &my_rendezvous_port) {
  pimpl_->StartPingRendezvous(directly_connected, my_rendezvous_ip,
                              my_rendezvous_port);
}

void TransportUDT::StopPingRendezvous() {
  pimpl_->StopPingRendezvous();
}

bool TransportUDT::CanConnect(const std::string &ip, const uint16_t &port) {
  return pimpl_->CanConnect(ip, port);
}

bool TransportUDT::IsAddrUsable(const std::string &local_ip,
                                const std::string &remote_ip,
                                const uint16_t &remote_port) {
  return pimpl_->IsAddrUsable(local_ip, remote_ip, remote_port);
}

bool TransportUDT::IsPortAvailable(const boost::uint16_t &port) {
  return pimpl_->IsPortAvailable(port);
}

};  // namespace transport
