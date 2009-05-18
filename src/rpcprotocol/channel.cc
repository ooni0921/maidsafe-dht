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
#include "rpcprotocol/channelimpl.h"

namespace rpcprotocol {

Controller::Controller() : controller_pimpl_(new ControllerImpl()) {}

Controller::~Controller() {}

void Controller::SetFailed(const std::string &str) {
  controller_pimpl_->SetFailed(str);
}

void Controller::Reset() {
  controller_pimpl_->Reset();
}

bool Controller::Failed() const {
  return controller_pimpl_->Failed();
}

std::string Controller::ErrorText() const {
  return controller_pimpl_->ErrorText();
}

void Controller::StartCancel() {
  controller_pimpl_->StartCancel();
}

bool Controller::IsCanceled() const {
  return controller_pimpl_->IsCanceled();
}

void Controller::NotifyOnCancel(google::protobuf::Closure* done) {
  controller_pimpl_->NotifyOnCancel(done);
}

void Controller::set_remote_ip(const std::string &ip) {
  controller_pimpl_->set_remote_ip(ip);
}

void Controller::set_remote_port(const uint16_t &port) {
  controller_pimpl_->set_remote_port(port);
}

std::string Controller::remote_ip() const {
  return controller_pimpl_->remote_ip();
}

uint16_t Controller::remote_port() const {
  return controller_pimpl_->remote_port();
}

void Controller::set_timeout(const int &seconds) {
  controller_pimpl_->set_timeout(seconds);
}

int Controller::timeout() const {
  return controller_pimpl_->timeout();
}

Channel::Channel(boost::shared_ptr<rpcprotocol::ChannelManager> channelmanager)
    : pimpl_(new ChannelImpl(channelmanager)) {}

Channel::Channel(boost::shared_ptr<rpcprotocol::ChannelManager> channelmanager,
                 const std::string &ip,
                 const boost::uint16_t &port,
                 const bool &local)
    : pimpl_(new ChannelImpl(channelmanager, ip, port, local)) {}

Channel::~Channel() {}

void Channel::CallMethod(const google::protobuf::MethodDescriptor *method,
                         google::protobuf::RpcController *controller,
                         const google::protobuf::Message *request,
                         google::protobuf::Message *response,
                         google::protobuf::Closure *done) {
  pimpl_->CallMethod(method, controller, request, response, done);
}

void Channel::SetService(google::protobuf::Service* service) {
  pimpl_->SetService(service);
}

void Channel::HandleRequest(const RpcMessage &request,
                            const boost::uint32_t &connection_id) {
  pimpl_->HandleRequest(request, connection_id);
}

}  // namespace rpcprotocol
