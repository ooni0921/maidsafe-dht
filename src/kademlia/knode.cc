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

#include "maidsafe/knode-api.h"
#include "kademlia/knodeimpl.h"

namespace kad {

KNode::KNode(rpcprotocol::ChannelManager *channel_manager,
      transport::Transport *trans, node_type type,
      const std::string &private_key, const std::string &public_key,
      const bool &port_forwarded, const bool &use_upnp)
      : pimpl_(new KNodeImpl(channel_manager, trans, type, private_key,
        public_key, port_forwarded, use_upnp)) {}

KNode::KNode(rpcprotocol::ChannelManager *channel_manager,
      transport::Transport *trans, node_type type, const boost::uint16_t k,
      const int &alpha, const int &beta, const int &refresh_time,
      const std::string &private_key, const std::string &public_key,
      const bool &port_forwarded, const bool &use_upnp)
      : pimpl_(new KNodeImpl(channel_manager, trans, type, k, alpha, beta,
        refresh_time, private_key, public_key, port_forwarded, use_upnp)) {}

KNode::~KNode() {}

void KNode::Join(const std::string &node_id, const std::string &kad_config_file,
      base::callback_func_type cb) {
  pimpl_->Join(node_id, kad_config_file, cb);
}

void KNode::Join(const std::string &kad_config_file,
      base::callback_func_type cb) {
  pimpl_->Join(kad_config_file, cb);
}

void KNode::Join(const std::string &node_id, const std::string &kad_config_file,
      const std::string &external_ip, const boost::uint16_t &external_port,
      base::callback_func_type cb) {
  pimpl_->Join(node_id, kad_config_file, external_ip, external_port, cb);
}

void KNode::Join(const std::string &kad_config_file,
      const std::string &external_ip, const boost::uint16_t &external_port,
      base::callback_func_type cb) {
  pimpl_->Join(kad_config_file, external_ip, external_port, cb);
}

void KNode::Leave() {
  pimpl_->Leave();
}

void KNode::StoreValue(const std::string &key,
                       const SignedValue &value,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       const boost::uint32_t &ttl,
                       base::callback_func_type cb) {
  pimpl_->StoreValue(key, value, public_key, signed_public_key, signed_request,
                     ttl, cb);
}

void KNode::StoreValue(const std::string &key,
                       const std::string &value,
                       const boost::uint32_t &ttl,
                       base::callback_func_type cb) {
  pimpl_->StoreValue(key, value, ttl, cb);
}

void KNode::FindValue(const std::string &key, const bool &check_alt_store,
      base::callback_func_type cb) {
  pimpl_->FindValue(key, check_alt_store, cb);
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

int KNode::AddContact(Contact new_contact, const float & rtt,
      const bool &only_db) {
  return pimpl_->AddContact(new_contact, rtt, only_db);
}

void KNode::RemoveContact(const std::string &node_id) {
  pimpl_->RemoveContact(node_id);
}

bool KNode::GetContact(const std::string &id, Contact *contact) {
  return pimpl_->GetContact(id, contact);
}

bool KNode::FindValueLocal(const std::string &key,
                           std::vector<std::string> *values) {
  return pimpl_->FindValueLocal(key, values);
}

bool KNode::StoreValueLocal(const std::string &key,
      const std::string &value, const boost::uint32_t &ttl) {
  return pimpl_->StoreValueLocal(key, value, ttl);
}

bool KNode::RefreshValueLocal(const std::string &key,
      const std::string &value, const boost::uint32_t &ttl) {
  return pimpl_->RefreshValueLocal(key, value, ttl);
}

void KNode::GetRandomContacts(const int &count,
                              const std::vector<Contact> &exclude_contacts,
                              std::vector<Contact> *contacts) {
  pimpl_->GetRandomContacts(count, exclude_contacts, contacts);
}

void KNode::HandleDeadRendezvousServer(const bool &dead_server) {
  pimpl_->HandleDeadRendezvousServer(dead_server);
}

connect_to_node KNode::CheckContactLocalAddress(const std::string &id,
                                                const std::string &ip,
                                                const uint16_t &port,
                                                const std::string &ext_ip) {
  return pimpl_->CheckContactLocalAddress(id, ip, port, ext_ip);
}

void KNode::UpdatePDRTContactToRemote(const std::string &node_id,
                                      const std::string &host_ip) {
  pimpl_->UpdatePDRTContactToRemote(node_id, host_ip);
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

boost::uint32_t KNode::KeyLastRefreshTime(const std::string &key,
      const std::string &value) {
  return pimpl_->KeyLastRefreshTime(key, value);
}
boost::uint32_t KNode::KeyExpireTime(const std::string &key,
      const std::string &value) {
  return pimpl_->KeyExpireTime(key, value);
}

bool KNode::HasRSAKeys() {
  return pimpl_->HasRSAKeys();
}

boost::uint32_t KNode::KeyValueTTL(const std::string &key,
      const std::string &value) const {
  return pimpl_->KeyValueTTL(key, value);
}

void KNode::SetAlternativeStore(base::AlternativeStore* alternative_store) {
  pimpl_->SetAlternativeStore(alternative_store);
}

base::AlternativeStore *KNode::alternative_store() {
  return pimpl_->alternative_store();
}

void InsertKadContact(const std::string &key,
                      const kad::Contact &new_contact,
                      std::vector<kad::Contact> *contacts) {
  std::list<kad::Contact> contact_list(contacts->begin(), contacts->end());
  contact_list.push_back(new_contact);
  SortContactList(&contact_list, key);
  contacts->clear();
  for (std::list<kad::Contact>::iterator it = contact_list.begin();
       it != contact_list.end(); ++it) {
    contacts->push_back(*it);
  }
}

}  // namespace kad
