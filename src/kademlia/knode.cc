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
#include "kademlia/knodeimpl.h"

namespace kad {

KNode::KNode(const std::string &datastore_dir,
             boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
             node_type type) : pimpl_(new KNodeImpl(datastore_dir,
                                                    channel_manager,
                                                    type)) {}

KNode::KNode(const std::string &datastore_dir,
             boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
             node_type type,
             const boost::uint16_t k,
             const int &alpha,
             const int &beta) : pimpl_(new KNodeImpl(datastore_dir,
                                                     channel_manager,
                                                     type,
                                                     k,
                                                     alpha,
                                                     beta)) {}

KNode::~KNode() {}

void KNode::Join(const std::string &node_id,
                 const std::string &kad_config_file,
                 base::callback_func_type cb,
                 const bool &port_forwarded) {
  pimpl_->Join(node_id, kad_config_file, cb, port_forwarded);
}

void KNode::Leave() {
  pimpl_->Leave();
}

void KNode::StoreValue(const std::string &key,
                       const std::string &value,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       base::callback_func_type cb) {
  pimpl_->StoreValue(key, value, public_key, signed_public_key, signed_request,
                     cb);
}

void KNode::FindValue(const std::string &key, base::callback_func_type cb) {
  pimpl_->FindValue(key, cb);
}

void KNode::FindNode(const std::string &node_id,
                     base::callback_func_type cb,
                     const bool &local) {
  pimpl_->FindNode(node_id, cb, local);
}

void KNode::FindCloseNodes(const std::string &node_id,
                           base::callback_func_type cb) {
  pimpl_->FindCloseNodes(node_id, cb);
}

void KNode::FindKClosestNodes(const std::string &key,
                              std::vector<Contact> *close_nodes,
                              const std::vector<Contact> &exclude_contacts) {
  pimpl_->FindKClosestNodes(key, close_nodes, exclude_contacts);
}

void KNode::Ping(const std::string &node_id, base::callback_func_type cb) {
  pimpl_->Ping(node_id, cb);
}

void KNode::Ping(const Contact &remote, base::callback_func_type cb) {
  pimpl_->Ping(remote, cb);
}

void KNode::AddContact(Contact new_contact, bool only_db) {
  pimpl_->AddContact(new_contact, only_db);
}

void KNode::RemoveContact(const std::string &node_id) {
  pimpl_->RemoveContact(node_id);
}

bool KNode::GetContact(const std::string &id, Contact *contact) {
  return pimpl_->GetContact(id, contact);
}

void KNode::FindValueLocal(const std::string &key,
                           std::vector<std::string> &values) {
  pimpl_->FindValueLocal(key, values);
}

void KNode::StoreValueLocal(const std::string &key,
                            const std::string &value) {
  pimpl_->StoreValueLocal(key, value);
}

void KNode::GetRandomContacts(const int &count,
                              const std::vector<Contact> &exclude_contacts,
                              std::vector<Contact> *contacts) {
  pimpl_->GetRandomContacts(count, exclude_contacts, contacts);
}

void KNode::HandleDeadRendezvousServer(const bool &dead_server,
                                       const std::string &ip,
                                       const uint16_t &port) {
  pimpl_->HandleDeadRendezvousServer(dead_server, ip, port);
}

connect_to_node KNode::CheckContactLocalAddress(const std::string &id,
                                                const std::string &ip,
                                                const uint16_t &port,
                                                const std::string &ext_ip) {
  return pimpl_->CheckContactLocalAddress(id, ip, port, ext_ip);
}

void KNode::UpdatePDRTContactToRemote(const std::string &node_id) {
  pimpl_->UpdatePDRTContactToRemote(node_id);
}

ContactInfo KNode::contact_info() const {
  return pimpl_->contact_info();
}

std::string KNode::node_id() const {
  return pimpl_->node_id();
}

std::string KNode::host_ip() const {
  return pimpl_->host_ip();
}

boost::uint16_t KNode::host_port() const {
  return pimpl_->host_port();
}

std::string KNode::local_host_ip() const {
  return pimpl_->local_host_ip();
}

boost::uint16_t KNode::local_host_port() const {
  return pimpl_->local_host_port();
}

std::string KNode::rv_ip() const {
  return pimpl_->rv_ip();
}

boost::uint16_t KNode::rv_port() const {
  return pimpl_->rv_port();
}

bool KNode::is_joined() const {
  return pimpl_->is_joined();
}

KadRpcs* KNode::kadrpcs() {
  return pimpl_->kadrpcs();
}
}  // namespace kad
