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

#include "maidsafe/channelmanager-api.h"
#include "protobuf/general_messages.pb.h"
#include "rpcprotocol/channelmanagerimpl.h"

namespace rpcprotocol {

ChannelManager::ChannelManager(transport::Transport *ptransport)
      : pimpl_(new ChannelManagerImpl(ptransport)) {}

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

int ChannelManager::Start() {
  return pimpl_->Start();
}
int ChannelManager::Stop() {
  return pimpl_->Stop();
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

void ChannelManager::AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &req_id, const int &timeout) {
  pimpl_->AddTimeOutRequest(connection_id, req_id, timeout);
}

void ChannelManager::AddChannelId(boost::uint32_t *id) {
  pimpl_->AddChannelId(id);
}

void ChannelManager::RemoveChannelId(const boost::uint32_t &id) {
  pimpl_->RemoveChannelId(id);
}

bool ChannelManager::RegisterNotifiersToTransport() {
  return pimpl_->RegisterNotifiersToTransport();
}
}  // namespace rpcprotocol
