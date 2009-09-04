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

#include "maidsafe/maidsafe-dht.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "rpcprotocol/channelmanagerimpl.h"

namespace rpcprotocol {

ChannelManager::ChannelManager() : pimpl_(new ChannelManagerImpl) {}

ChannelManager::~ChannelManager() {}

void ChannelManager::AddPendingRequest(const boost::uint32_t &req_id,
      PendingReq req) {
  pimpl_->AddPendingRequest(req_id, req);
}

bool ChannelManager::DeletePendingRequest(const boost::uint32_t &req_id) {
  return pimpl_->DeletePendingRequest(req_id);
}

void ChannelManager::AddReqToTimer(const boost::uint32_t &req_id,
      const int &timeout) {
  pimpl_->AddReqToTimer(req_id, timeout);
}

boost::uint32_t ChannelManager::CreateNewId() {
  return pimpl_->CreateNewId();
}

void ChannelManager::RegisterChannel(const std::string &service_name,
      Channel* channel) {
  pimpl_->RegisterChannel(service_name, channel);
}

int ChannelManager::StartTransport(boost::uint16_t port,
    boost::function<void(const bool&, const std::string&,
                         const boost::uint16_t&)> notify_dead_server) {
  return pimpl_->StartTransport(port, notify_dead_server);
}

int ChannelManager::StopTransport() {
  return pimpl_->StopTransport();
}

void ChannelManager::CleanUpTransport() {
  pimpl_->CleanUpTransport();
}

void ChannelManager::MessageArrive(const RpcMessage &msg,
      const boost::uint32_t &connection_id, const float &rtt) {
  pimpl_->MessageArrive(msg, connection_id, rtt);
}

void ChannelManager::UnRegisterChannel(const std::string &service_name) {
  pimpl_->UnRegisterChannel(service_name);
}

void ChannelManager::ClearChannels() {
  pimpl_->ClearChannels();
}

void ChannelManager::ClearCallLaters() {
  pimpl_->ClearCallLaters();
}

boost::shared_ptr<transport::Transport> ChannelManager::ptransport() {
  return pimpl_->ptransport();
}

boost::uint16_t ChannelManager::external_port() const {
  return pimpl_->external_port();
}

bool ChannelManager::CheckConnection(const std::string &ip,
      const uint16_t &port) {
  return pimpl_->CheckConnection(ip, port);
}

bool ChannelManager::CheckLocalAddress(const std::string &local_ip,
    const std::string &remote_ip, const uint16_t &remote_port) {
  return pimpl_->CheckLocalAddress(local_ip, remote_ip, remote_port);
}

void ChannelManager::RequestSent(const boost::uint32_t &connection_id,
    const bool &success) {
  pimpl_->RequestSent(connection_id, success);
}

void ChannelManager::AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &req_id, const int &timeout) {
  return pimpl_->AddTimeOutRequest(connection_id, req_id, timeout);
}

void ChannelManager::AddChannelId(boost::uint32_t *id) {
  pimpl_->AddChannelId(id);
}

void ChannelManager::RemoveChannelId(const boost::uint32_t &id) {
  pimpl_->RemoveChannelId(id);
}

int ChannelManager::StartLocalTransport(const boost::uint16_t &port) {
  pimpl_->StartLocalTransport(port);
}

void ChannelManager::OnlineStatusChanged(const bool &online) {
  pimpl_->OnlineStatusChanged(online);
}

}  // namespace rpcprotocol
