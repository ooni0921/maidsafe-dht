/*
Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*ritten permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: haiyang
 */

#include "kademlia/knode.h"
#include <boost/assert.hpp>
#include <boost/bind.hpp>
#include <google/protobuf/descriptor.h>
#include <iostream>  // NOLINT Fraser - required for handling .kadconfig file
#include <vector>
#include "base/config.h"
#include "base/crypto.h"
#include "base/tri_logger.h"
#include "base/utils.h"
#include "kademlia/contact.h"
#include "kademlia/datastore.h"
#include "kademlia/kademlia.h"
#include "kademlia/kadservice.h"
#include "kademlia/kadutils.h"
#include "protobuf/contact_info.pb.h"
#include "rpcprotocol/channelmanager.h"
#include "rpcprotocol/channel.h"

namespace fs = boost::filesystem;

namespace kad {
// some tools which will be used in the implementation of KNode class
struct ContactAndTargetKey {
  ContactAndTargetKey() : contact(), target_key() {}
  Contact contact;
  std::string target_key;
};

bool CompareContact(const ContactAndTargetKey &first,
    const ContactAndTargetKey &second) {
  if (first.contact.node_id() == "")
    return true;
  else if (second.contact.node_id() == "")
    return false;
  if (kademlia_distance(first.contact.node_id(), first.target_key) <
      kademlia_distance(second.contact.node_id(), second.target_key))
    return true;
  else
    return false;
}
// sort the contact list according the distance to the target key
void SortContactList(std::list<Contact> *contact_list,
    const std::string &target_key) {
  if (contact_list->size() == 0) {
    return;
  }
  std::list<ContactAndTargetKey> temp_list;
  std::list<Contact>::iterator it;
  // clone the contacts into a temporary list together with the target key
  for (it = contact_list->begin(); it != contact_list->end(); ++it) {
    ContactAndTargetKey new_ck;
    new_ck.contact = *it;
    new_ck.target_key = target_key;
    temp_list.push_back(new_ck);
  }
  temp_list.sort(CompareContact);
  // restore the sorted contacts from the temporary list.
  contact_list->clear();
  std::list<ContactAndTargetKey>::iterator it1;
  for (it1 = temp_list.begin(); it1 != temp_list.end(); ++it1) {
    contact_list->push_back(it1->contact);
  }
}

// a dummy callback function
void dummy_callback(const std::string&) {}
void dummy_downlist_callback(DownlistResponse *response) {
  delete response;
}

KNode::KNode(const std::string &datastore_dir,
             base::CallLaterTimer *timer,
             boost::recursive_mutex *mutex,
             boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
             node_type type)
    : pmutex_(mutex),
      ptimer_(timer),
      pchannel_manager_(channel_manager),
      pservice_channel_(),
      pdata_store_(new DataStore()),
      premote_service_(),
      kadrpcs_(channel_manager),
      is_joined_(false),
      prouting_table_(),
      node_id_(),
      host_ip_(channel_manager->external_ip()),
      fake_client_node_id_(),
      type_(type),
      host_port_(channel_manager->external_port()),
      rv_ip_(),
      rv_port_(0),
      bootstrapping_nodes_(),
      K_(K),
      alpha_(kAlpha),
      beta_(kBeta),
      dead_rendezvous_server_(),
      refresh_routine_started_(false),
      kad_config_path_(),
      routingtable_(),
      local_host_ip_(),
      local_host_port_(0),
      upnp_started_(false),
      upnp_ios_(),
      upnp_(),
      upnp_half_open_(NULL),
      upnp_user_agent_("maidsafe"),
      upnp_mapped_port_(0),
      upnp_udp_map_(0) {
  try {
    if (!fs::exists(datastore_dir))
      fs::create_directories(datastore_dir);
  }
  catch(const std::exception &ex_) {
    printf("%s\n", ex_.what());
  }
  fs::path db_(datastore_dir, fs::native);
  db_ /= "datastore.db";
  pdata_store_->Init(db_.string(), kReuseDatabase);
  if (host_ip_ == "") {
    // Get local address as the external ip address...??!!
    boost::asio::ip::address local_address;
    if (base::get_local_address(&local_address)) {
      host_ip_ = local_address.to_string();
      local_host_ip_ = local_address.to_string();
    }
  }
}

KNode::KNode(const std::string &datastore_dir,
             base::CallLaterTimer *timer,
             boost::recursive_mutex *mutex,
             boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
             node_type type,
             const boost::uint16_t k,
             const int &alpha,
             const int &beta)
    : pmutex_(mutex),
      ptimer_(timer),
      pchannel_manager_(channel_manager),
      pservice_channel_(),
      pdata_store_(new DataStore()),
      premote_service_(),
      kadrpcs_(channel_manager),
      is_joined_(false),
      prouting_table_(),
      node_id_(),
      host_ip_(channel_manager->external_ip()),
      fake_client_node_id_(),
      type_(type),
      host_port_(channel_manager->external_port()),
      rv_ip_(),
      rv_port_(0),
      bootstrapping_nodes_(),
      K_(k),
      alpha_(alpha),
      beta_(beta),
      dead_rendezvous_server_(),
      refresh_routine_started_(false),
      kad_config_path_(),
      routingtable_(),
      local_host_ip_(),
      local_host_port_(0),
      upnp_started_(false),
      upnp_ios_(),
      upnp_(),
      upnp_half_open_(NULL),
      upnp_user_agent_("maidsafe"),
      upnp_mapped_port_(0),
      upnp_udp_map_(0) {
  try {
    if (!fs::exists(datastore_dir))
      fs::create_directories(datastore_dir);
  }
  catch(const std::exception &ex_) {
    printf("%s\n", ex_.what());
  }
  fs::path db_(datastore_dir, fs::native);
  db_ /= "datastore.db";
  pdata_store_->Init(db_.string(), kReuseDatabase);
  if (host_ip_ == "") {
    // Get local address as the external ip address...??!!
    boost::asio::ip::address local_address;
    if (base::get_local_address(&local_address)) {
      host_ip_ = local_address.to_string();
      local_host_ip_ = local_address.to_string();
    }
  }
}

KNode::~KNode() {
//  printf("In KNode (on port %i) destructor.\n", host_port_);
  if (is_joined_) {
    base::pd_scoped_lock guard(*pmutex_);
    UnRegisterKadService();
    is_joined_ = false;
    pdata_store_->Close();
  }
  if (upnp_started_ && upnp_mapped_port_ > 0) {
    UnMapUPnP();
  }
  upnp_started_ = false;
  upnp_mapped_port_ = 0;
}

inline void KNode::CallbackWithFailure(base::callback_func_type cb) {
  base::GeneralResponse result_msg;
  result_msg.set_result(kRpcResultFailure);
  std::string result;
  result_msg.SerializeToString(&result);
  cb(result);
}

void KNode::Bootstrap_Callback(const BootstrapResponse *response,
    BootstrapData data) {
  std::string result_str;
  BootstrapResponse result_msg;
  if (response->IsInitialized()) {
    result_msg = *response;
  } else {
    result_msg.set_result(kRpcResultFailure);
  }
  result_msg.SerializeToString(&result_str);
  data.cb(result_str);
  delete response;
}

void KNode::Bootstrap(const std::string &bootstrap_ip,
  const boost::uint16_t &bootstrap_port, base::callback_func_type cb) {
  struct BootstrapData data = {cb, bootstrap_ip, bootstrap_port};
  // send RPC to a bootstrapping node candidate
  BootstrapResponse *resp = new BootstrapResponse();
  google::protobuf::Closure *done = google::protobuf::NewCallback<
      KNode, const BootstrapResponse*, struct BootstrapData> (this,
      &KNode::Bootstrap_Callback, resp, data);
  kadrpcs_.Bootstrap(node_id(), host_ip_, host_port_, bootstrap_ip,
    bootstrap_port, resp, done);
}

void KNode::Join_Bootstrapping_Iteration_Client(const std::string& result,
    boost::shared_ptr<struct BootstrapArgs> args,
    const std::string bootstrap_ip, const boost::uint16_t bootstrap_port,
    const std::string local_bs_ip, const boost::uint16_t local_bs_port) {
  if (args->is_callbacked)
    return;
  --args->active_process;
  BootstrapResponse result_msg;
  if ((result_msg.ParseFromString(result)) &&
      (result_msg.result() == kRpcResultSuccess)) {
    kad::Contact bootstrap_node(result_msg.bootstrap_id(), bootstrap_ip,
      bootstrap_port, local_bs_ip, local_bs_port);
    AddContact(bootstrap_node);
    host_ip_ = result_msg.newcomer_ext_ip();
    host_port_ = result_msg.newcomer_ext_port();
    kadrpcs_.set_info(contact_info());
    args->is_callbacked = true;
    std::vector<Contact> start_up_short_list;
    IterativeLookUp(node_id_, args->cached_nodes, BOOTSTRAP, args->cb);
    // start a schedule to delete expired key/value pairs only once
    if (!refresh_routine_started_) {
      ptimer_->AddCallLater(kRefreshTime*1000, boost::bind(
        &KNode::RefreshRoutine, this));
      refresh_routine_started_ = true;
    }
  } else if (!args->cached_nodes.empty()) {
    Contact bootstrap_candidate = args->cached_nodes.back();
    args->cached_nodes.pop_back();  // inefficient!!!!
    Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
      boost::bind(&KNode::Join_Bootstrapping_Iteration_Client, this, _1, args,
      bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
      bootstrap_candidate.local_ip(), bootstrap_candidate.local_port()));
    ++args->active_process;
  } else if (args->active_process == 0) {
    base::GeneralResponse local_result;
    local_result.set_result(kRpcResultFailure);
    std::string local_result_str;
    local_result.SerializeToString(&local_result_str);
    args->is_callbacked = true;
    args->cb(local_result_str);
  }
}

void KNode::Join_Bootstrapping_Iteration(const std::string& result,
    boost::shared_ptr<struct BootstrapArgs> args,
    const std::string bootstrap_ip, const boost::uint16_t bootstrap_port,
    const std::string local_bs_ip, const boost::uint16_t local_bs_port) {
  if (args->is_callbacked)
    return;
  --args->active_process;
  BootstrapResponse result_msg;
  if ((result_msg.ParseFromString(result)) &&
      (result_msg.result() == kRpcResultSuccess)) {
    kad::Contact bootstrap_node(result_msg.bootstrap_id(), bootstrap_ip,
      bootstrap_port, local_bs_ip, local_bs_port);
    AddContact(bootstrap_node);
    bool directlyconnected = false;
    if (host_ip_ == result_msg.newcomer_ext_ip() &&
        host_port_ == result_msg.newcomer_ext_port())
      directlyconnected = true;
    host_ip_ = result_msg.newcomer_ext_ip();
    host_port_ = result_msg.newcomer_ext_port();
    if (result_msg.nat_type() == 1) {
      // Direct connection
      pchannel_manager_->ptransport()->StartPingRendezvous(directlyconnected,
        bootstrap_node.host_ip(), bootstrap_node.host_port());
      rv_ip_ = "";
      rv_port_ = 0;
    } else if (result_msg.nat_type() == 2) {
      // need rendezvous server
      rv_ip_ = bootstrap_node.host_ip();
      rv_port_ = bootstrap_node.host_port();
      pchannel_manager_->ptransport()->StartPingRendezvous(directlyconnected,
        rv_ip_, rv_port_);
    } else if (result_msg.nat_type() == 3) {
      // behind symmetric router or no connection
      UPnPMap(local_host_port_);
      if (upnp_mapped_port_ != 0) {
        host_port_ = upnp_mapped_port_;
      } else {
        base::GeneralResponse local_result;
        local_result.set_result(kRpcResultFailure);
        std::string local_result_str;
        local_result.SerializeToString(&local_result_str);
        args->is_callbacked = true;
        UnRegisterKadService();
        args->cb(local_result_str);
        return;
      }
    }
    kadrpcs_.set_info(contact_info());
    args->is_callbacked = true;
    std::vector<Contact> start_up_short_list;
    IterativeLookUp(node_id_, start_up_short_list, BOOTSTRAP, args->cb);
    // start a schedule to delete expired key/value pairs only once
    if (!refresh_routine_started_) {
      ptimer_->AddCallLater(kRefreshTime*1000, boost::bind(
        &KNode::RefreshRoutine, this));
      refresh_routine_started_ = true;
    }
  } else if (!args->cached_nodes.empty()) {
    Contact bootstrap_candidate = args->cached_nodes.back();
    args->cached_nodes.pop_back();  // inefficient!!!!
    Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
      boost::bind(&KNode::Join_Bootstrapping_Iteration, this, _1, args,
      bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
      bootstrap_candidate.local_ip(), bootstrap_candidate.local_port()));
    ++args->active_process;
  } else if (args->active_process == 0) {
    base::GeneralResponse local_result;
    local_result.set_result(kRpcResultSuccess);
    std::string local_result_str;
    local_result.SerializeToString(&local_result_str);
    args->is_callbacked = true;
    rv_ip_ = "";
    rv_port_ = 0;
    args->cb(local_result_str);
  }
}

void KNode::Join_Bootstrapping(base::callback_func_type cb,
                               std::vector<Contact> &cached_nodes) {
  base::pd_scoped_lock guard(*pmutex_);
  if (cached_nodes.empty()) {
    base::GeneralResponse local_result;
    std::string local_result_str;
    if (type_ != CLIENT) {
      local_result.set_result(kRpcResultSuccess);
      is_joined_ = true;
      // since it is a 1 network node, so it has no rendezvous server to ping
      pchannel_manager_->ptransport()->StartPingRendezvous(true,
        rv_ip_, rv_port_);
    } else {
      // Client nodes can not start a network on their own
      local_result.set_result(kRpcResultFailure);
      UnRegisterKadService();
    }
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
    return;
  }
  // Clients don't need to do nat detection
//  if (type_ == CLIENT) {
//    IterativeLookUp(node_id_, cached_nodes, BOOTSTRAP, cb);
//    return;
//  }

  boost::shared_ptr<struct BootstrapArgs> args(new struct BootstrapArgs);
  args->cached_nodes = cached_nodes;
  args->cb = cb;
  args->active_process = 0;
  args->is_callbacked = false;
  int parallel_size = 0;
  if (static_cast<int>(cached_nodes.size()) > 6)
    parallel_size = 6;  // TODO(Fraser#5#): 2009-04-06 - Make it constant later
  else
    parallel_size = static_cast<int>(cached_nodes.size());
  for (int i = 0; i < parallel_size; ++i) {
    Contact bootstrap_candidate = cached_nodes.back();
    cached_nodes.pop_back();
    if (bootstrap_candidate == dead_rendezvous_server_) {
      if (cached_nodes.empty())
        break;
      bootstrap_candidate = cached_nodes.back();
      cached_nodes.pop_back();
    }
    if (type_ == CLIENT) {
      Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
        boost::bind(&KNode::Join_Bootstrapping_Iteration_Client, this, _1, args,
        bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
        bootstrap_candidate.local_ip(), bootstrap_candidate.local_port()));
    } else {
      Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
        boost::bind(&KNode::Join_Bootstrapping_Iteration, this, _1, args,
        bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
        bootstrap_candidate.local_ip(), bootstrap_candidate.local_port()));
    }
    ++args->active_process;
  }
}

void KNode::Join_RefreshNode(base::callback_func_type cb) {
//  printf("Node address: %s:%d\n", host_ip_.c_str(), host_port_);

  // build list of bootstrapping nodes
  LoadBootstrapContacts();
  // Initiate the Kademlia joining sequence - perform a search for this
  // node's own ID
  kadrpcs_.set_info(contact_info());
  // is_joined_ = true;
  Join_Bootstrapping(cb, bootstrapping_nodes_);
}

void KNode::Join(const std::string &node_id,
                 const std::string &kad_config_file,
                 base::callback_func_type cb) {
  if (is_joined_) {
    base::GeneralResponse local_result;
    local_result.set_result(kRpcResultSuccess);
    std::string local_result_str;
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
    return;
  }
  if (host_port_ == 0)
    host_port_ = pchannel_manager_->ptransport()->listening_port();
  local_host_port_ = pchannel_manager_->ptransport()->listening_port();
  routingtable_.reset(new base::PDRoutingTableHandler(base::itos(host_port_)));
  // Adding the services
  RegisterKadService();
  // if node_id is equal to "", generate a random kad ID and save it
  if (node_id.size() == 0) {
//    // check whether there is stored node id
//    std::vector<std::string> node_ids;
//    pdata_store_->LoadItem("node_id", node_ids);
//    if ((!node_ids.empty())&&(node_ids.front().size() != 0)) {
//      // An old node id is available, let's reuse that
//      node_id_ = node_ids.front();
//      node_ids.clear();
//    } else {

    node_id_ = vault_random_id();
    boost::uint32_t now = base::get_epoch_time();
    pdata_store_->StoreItem("node_id", node_id_, now, now);
//    }
  } else {
    node_id_ = node_id;
  }
  if (type_ == CLIENT) {
    fake_client_node_id_ = client_node_id();
  }

  // Set kad_config_path_
  kad_config_path_ = fs::path(kad_config_file, fs::native);
  std::string hex_node_id_("");
  base::encode_to_hex(node_id_, hex_node_id_);
  boost::shared_ptr<RoutingTable> rtng_table_(new RoutingTable(hex_node_id_));
  prouting_table_ = rtng_table_;
  Join_RefreshNode(cb);
}

void KNode::Leave() {
  if (is_joined_) {
    if (upnp_started_ && upnp_mapped_port_ > 0) {
      UnMapUPnP();
    }
    {
      base::pd_scoped_lock guard(*pmutex_);
      UnRegisterKadService();
      is_joined_ = false;
      upnp_started_ = false;
      upnp_mapped_port_ = 0;
      SaveBootstrapContacts();
      prouting_table_->Clear();
      routingtable_->Clear();
    }
  }
}

void KNode::SaveBootstrapContacts() {
  try {
    // If .kadconfig is locked, wait for up to 5 seconds, then start updating it
    fs::path lockfile(kad_config_path_.string() + ".lock", fs::native);
    int count = 0;
    while (fs::exists(lockfile) && count < 500) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      ++count;
    }
    // Create good copy of .kadconfig named lockfile.  If old lockfile still
    // exists, assume another thread failed to update .kadconfig, so overwrite
    // .kadconfig with lockfile.
    if (fs::exists(lockfile)) {
      fs::remove(kad_config_path_);
      fs::copy_file(lockfile, kad_config_path_);
    } else if (fs::exists(kad_config_path_)) {
      fs::copy_file(kad_config_path_, lockfile);
    }

    // Reload bootstrap vector from .kadconfig
    LoadBootstrapContacts();
    std::vector<Contact> exclude_contacts;
    int kbuckets = prouting_table_->KbucketSize();
    for (int i = 0; i < kbuckets; ++i) {
      std::vector<Contact> contacts_i;
      prouting_table_->GetContacts(i, &contacts_i, exclude_contacts);
      for (int j = 0; j < static_cast<int>(contacts_i.size()); ++j) {
        // store only the nodes that are directly connected to bootstrap vector
        if (contacts_i[j].rendezvous_ip() == "" &&
            contacts_i[j].rendezvous_port() == 0)
          bootstrapping_nodes_.push_back(contacts_i[j]);
      }
    }
    // Ensure vector is no greater than max allowed size
    int extra = bootstrapping_nodes_.size() - kMaxBootstrapContacts;
    if (extra > 0)
      bootstrapping_nodes_.erase(bootstrapping_nodes_.begin(),
                                 bootstrapping_nodes_.begin()+extra);
    // Save contacts to .kadconfig
    base::KadConfig kad_config;
    std::vector<Contact>::iterator it;
    for (it = bootstrapping_nodes_.begin();
         it < bootstrapping_nodes_.end();
         ++it) {
      base::KadConfig::Contact *kad_contact = kad_config.add_contact();
      kad_contact->set_node_id(it->node_id());
      kad_contact->set_ip(it->host_ip());
      kad_contact->set_port(it->host_port());
      kad_contact->set_local_ip(it->local_ip());
      kad_contact->set_local_port(it->local_port());
    }
    std::fstream output(kad_config_path_.string().c_str(),
      std::ios::out | std::ios::trunc | std::ios::binary);
    kad_config.SerializeToOstream(&output);
    output.close();
    // Delete lockfile
    fs::remove(lockfile);
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("Failed to update kademlia configuration file at %s.\n%s\n",
           kad_config_path_.string().c_str(), ex.what());
#endif
  }
}

int KNode::LoadBootstrapContacts() {
  // Get the saved contacts - most recent are listed last
  base::KadConfig kad_config;
  try {
    if (fs::exists(kad_config_path_)) {
      std::ifstream input_(kad_config_path_.string().c_str(),
                           std::ios::in | std::ios::binary);
      if (!kad_config.ParseFromIstream(&input_)) {
#ifdef DEBUG
        printf("Failed to parse kademlia configuration file.\n");
#endif
        return -1;
      }
      if (0 == kad_config.contact_size()) {
#ifdef DEBUG
        printf("Kademlia configuration file is empty.\n");
#endif
        return -1;
      }
    }
  }
  catch(const std::exception ex_) {
#ifdef DEBUG
    printf("Can't access kademlia configuration file at %s %s\n",
           kad_config_path_.string().c_str(),
           ex_.what());
#endif
    return -1;
  }
  bootstrapping_nodes_.clear();
  for (int i = 0; i < kad_config.contact_size(); ++i) {
    Contact bootstrap_contact(
        kad_config.contact(i).node_id(),
        kad_config.contact(i).ip(),
        static_cast<uint16_t>(kad_config.contact(i).port()),
        kad_config.contact(i).local_ip(),
        kad_config.contact(i).local_port());
//    printf("Added ip %s:%i to list\n", kad_config.contact(i).ip().c_str(),
//    kad_config.contact(i).port());
    bootstrapping_nodes_.push_back(bootstrap_contact);
  }
  return 0;
}

void KNode::RefreshRoutine() {
  if (is_joined_) {
    SaveBootstrapContacts();
    pdata_store_->DeleteExpiredValues();
    // Refresh the k-buckets
    std::vector<Contact> start_up_short_list;
    IterativeLookUp(node_id_, start_up_short_list,
      FIND_NODE, &dummy_callback);
    // schedule the next refresh routine
    ptimer_->AddCallLater(kRefreshTime*1000, boost::bind(
        &KNode::RefreshRoutine, this));
  } else {
    refresh_routine_started_ = false;
  }
}

void KNode::IterativeLookUp_CancelActiveProbe(Contact sender,
    boost::shared_ptr<IterativeLookUpData> data) {
  if (!is_joined_ && data->method != BOOTSTRAP) return;
  std::list<Contact>::iterator it;
  for (it = data->active_probes.begin(); it != data->active_probes.end();
      ++it) {
    if (sender.node_id() == data->key)
      data->wait_for_key = false;
    if (sender == *it && data->active_probes.size() > 0) {
      data->active_probes.erase(it);
      break;
    }
  }
  if (static_cast<int>(data->active_probes.size()) <= beta_ &&
      !data->wait_for_key) {
    // force iteration
    IterativeLookUp_SearchIteration(data);
  }
}

void KNode::IterativeLookUp_ExtendShortList(const FindResponse *response,
    FindCallbackArgs callback_data) {
  base::pd_scoped_lock gaurd(*pmutex_);
  if (!is_joined_ && callback_data.data->method != BOOTSTRAP) {
      delete response;
      return;
  }
  bool is_valid = true;
  if (!response->IsInitialized() && callback_data.data->method != BOOTSTRAP) {
    RemoveContact(callback_data.sender.node_id());
    is_valid = false;
    callback_data.data->dead_ids.push_back(callback_data.sender.node_id());
  }

  if (is_valid) {
    // Check id and retry if it was sent
    if (response->has_node_id() &&
        response->node_id() != callback_data.sender.node_id()) {
      if (callback_data.retry) {
        delete response;
        FindResponse *resp = new FindResponse();
        UpdatePDRTContactToRemote(callback_data.sender.node_id());
        callback_data.retry = false;
      // send RPC to this contact's remote address because local failed
        google::protobuf::Closure *done = google::protobuf::NewCallback<
            KNode, const FindResponse*, FindCallbackArgs >(this,
            &KNode::IterativeLookUp_ExtendShortList, resp, callback_data);
        if (callback_data.data->method == FIND_NODE ||
            callback_data.data->method == BOOTSTRAP) {
          if (callback_data.data->method == BOOTSTRAP) {
            kad::Contact tmp_contact(node_id(), host_ip_, host_port_,
              local_host_ip_, local_host_port_, rv_ip_, rv_port_);
            std::string contact_str;
            tmp_contact.SerialiseToString(&contact_str);
            resp->set_requester_ext_addr(contact_str);
          }
          kadrpcs_.FindNode(callback_data.data->key,
              callback_data.sender.host_ip(), callback_data.sender.host_port(),
              resp, done, false);
        } else if (callback_data.data->method == FIND_VALUE) {
          kadrpcs_.FindValue(callback_data.data->key,
              callback_data.sender.host_ip(), callback_data.sender.host_port(),
              resp, done, false);
        }
        return;
      }
    }
  }

  if ((!is_valid || response->result() == kRpcResultFailure) &&
      callback_data.data->method != BOOTSTRAP) {
    // callback can only be called once
    if (callback_data.data->is_callbacked) {
      if (callback_data.data->active_probes_after_callback > 0) {
        --callback_data.data->active_probes_after_callback;
      } else {
        delete response;
        return;
      }
      if (callback_data.data->active_probes_after_callback != 0) {
        delete response;
        return;
      }
      if (callback_data.data->method != BOOTSTRAP) {
        IterativeLookUp_SendDownlist(callback_data.data);
      }
      delete response;
      return;
    }
    std::list<Contact>::iterator it;
    for (it = callback_data.data->short_list.begin();
        it != callback_data.data->short_list.end(); ++it) {
      if (callback_data.sender == *it) {
        callback_data.data->short_list.erase(it);
        break;
      }
    }
    IterativeLookUp_CancelActiveProbe(callback_data.sender, callback_data.data);
    delete response;
    return;
  }
  // add/update routing table

//  std::string me, he;
//  base::encode_to_hex(node_id_, me);
//  base::encode_to_hex(callback_data.sender.node_id(), he);
//  printf("\t\tJust before AddContact (line 436) - my id  = %s\n", me.c_str());
//  printf("\t\tJust before AddContact (line 436) - his id = %s\n", he.c_str());
//  printf("\t\tHe returned %i contacts\n.", response->closest_nodes_size());

  AddContact(callback_data.sender);
//  // if this is a special lookup for boostrapping, save information returned
//  if (callback_data.data->method == BOOTSTRAP) {
//    kad::Contact tmp_contact;
//    if (tmp_contact.ParseFromString(response->requester_ext_addr())) {
//      this->host_ip_ = tmp_contact.host_ip();
//      this->host_port_ = tmp_contact.host_port();
//    }
// //    callback_data.data->method = FIND_NODE;
//  }
  // callback can only be called once
  // if ((callback_data.data->is_callbacked)||
  if (!is_joined_ && callback_data.data->method != BOOTSTRAP) {
    delete response;
    return;
  }

  if (callback_data.data->is_callbacked) {
    if (callback_data.data->active_probes_after_callback > 0) {
      --callback_data.data->active_probes_after_callback;
    } else {
      delete response;
      return;
    }
    if (callback_data.data->active_probes_after_callback != 0) {
      delete response;
      return;
    }
    if (callback_data.data->method != BOOTSTRAP) {
      IterativeLookUp_SendDownlist(callback_data.data);
    }
    delete response;
    return;
  }



  // Make sure the responding node is valid, and abort the operation if it isn't
  if (callback_data.sender.node_id() == node_id_) {
    IterativeLookUp_CancelActiveProbe(callback_data.sender,
        callback_data.data);
    delete response;
    return;
  }
  std::list<Contact>::iterator it;
  for (it = callback_data.data->active_contacts.begin();
      it != callback_data.data->active_contacts.end(); ++it) {
    if (*it == callback_data.sender) {
      IterativeLookUp_CancelActiveProbe(callback_data.sender,
          callback_data.data);
      delete response;
      return;
    }
  }
  // Mark this node as active
  callback_data.data->active_contacts.push_back(callback_data.sender);
  // extend the value list if there are any new values found
  std::list<std::string>::iterator it1;
  bool is_new;
  for (int i = 0; i < response->values_size(); ++i) {
    is_new = true;
    for (it1 = callback_data.data->find_value_result.begin();
      it1 != callback_data.data->find_value_result.end(); ++it1) {
      if (*it1 == response->values(i)) {
        is_new = false;
        break;
      }
    }
    if (is_new)
      callback_data.data->find_value_result.push_back(response->values(i));
  }
  // Now extend short list with the returned contacts
  std::list<Contact>::iterator it2;
  for (int i = 0; i < response->closest_nodes_size(); ++i) {
    Contact test_contact;
    if (!test_contact.ParseFromString(response->closest_nodes(i))) {
      continue;
    }
    AddContact(test_contact);
    is_new = true;
    for (it2 = callback_data.data->short_list.begin();
        it2 != callback_data.data->short_list.end(); ++it2) {
      if (test_contact == *it2) {
        is_new = false;
        break;
      }
    }
    if (is_new) {
      // add to the front
      Contact self_node(node_id_, host_ip_, host_port_, local_host_ip_,
          local_host_port_);
      if (test_contact != self_node)
        callback_data.data->short_list.push_front(test_contact);
    }
    // Implementation of downlist algorithm
    // Add to the downlist as a candidate with the is_down flag set to false
    // by default
    struct DownListCandidate candidate;
    candidate.node = test_contact;
    candidate.is_down = false;
    bool is_appended = false;
    std::list<struct DownListData>::iterator it5;
    for (it5 = callback_data.data->downlist.begin();
         it5 != callback_data.data->downlist.end(); ++it5) {
      if (it5->giver == callback_data.sender) {
        it5->candidate_list.push_back(candidate);
        is_appended = true;
        break;
      }
    }
    if (!is_appended) {
      struct DownListData downlist_data;
      downlist_data.giver = callback_data.sender;
      downlist_data.candidate_list.push_back(candidate);
      callback_data.data->downlist.push_back(downlist_data);
    }
    // End of implementation downlist algorithm
  }
  delete response;
  IterativeLookUp_CancelActiveProbe(callback_data.sender, callback_data.data);
}

void KNode::IterativeLookUp_Callback(
    boost::shared_ptr<IterativeLookUpData> data) {
  std::string ser_result;
  // If we're bootstrapping, we are only now finished.  In this case the
  // callback should be of type base::GeneralResponse
  if (data->method == BOOTSTRAP) {
    base::GeneralResponse result;
    if (data->active_contacts.begin() == data->active_contacts.end()) {
      result.set_result(kRpcResultFailure);
      is_joined_ = false;
    } else {
      result.set_result(kRpcResultSuccess);
      is_joined_ = true;
    }
    result.SerializeToString(&ser_result);
  } else {
    if (!is_joined_) return;
    // take K closest contacts from active contacts as the closest nodes
    std::list<Contact>::iterator it1;
    int count;
    FindResponse result;
    for (it1 = data->active_contacts.begin(), count = 0;
      (it1 != data->active_contacts.end())&&(count < K_); ++it1, ++count) {
      std::string ser_contact;
      if (it1->SerialiseToString(&ser_contact))
        result.add_closest_nodes(ser_contact);
    }
    if ((data->method == FIND_VALUE) &&
        (data->find_value_result.size() == 0)) {
      result.set_result(kRpcResultFailure);
    } else if ((data->method != FIND_VALUE) &&
             (result.closest_nodes_size() == 0)) {
      result.set_result(kRpcResultFailure);
    } else {
      result.set_result(kRpcResultSuccess);
    }
    std::list<std::string>::iterator it2;
    for (it2 = data->find_value_result.begin();
        it2 != data->find_value_result.end(); ++it2) {
      result.add_values(*it2);
    }
    result.SerializeToString(&ser_result);
  }
  data->is_callbacked = true;
  // fake sender
//  ContactInfo *sender_info = result.mutable_sender_info();
//  sender_info->set_node_id("abc");
//  sender_info->set_ip("ip");
//  sender_info->set_port(0);
  data->cb(ser_result);
  data->active_probes_after_callback = data->active_probes.size();
  if (data->active_probes_after_callback != 0) {
    return;
  }
  IterativeLookUp_SendDownlist(data);
}

void KNode::IterativeLookUp_SendDownlist(
      boost::shared_ptr<IterativeLookUpData> data) {
  // Implementation of downlist algorithm
  // At the end of the search the corresponding entries of the downlist are sent
  // to all peers which gave those entries to this node during its search
  if (data->downlist_sent || !is_joined_) return;
  if (data->dead_ids.empty()) {
    data->downlist_sent = true;
    return;
  }
  std::list<struct DownListData>::iterator it1;

  for (it1 = data->downlist.begin(); it1 != data->downlist.end(); ++it1) {
    std::vector<std::string> downlist;
    std::list<struct DownListCandidate>::iterator it2;
    for (it2 = it1->candidate_list.begin(); it2 != it1->candidate_list.end();
        ++it2) {
      std::list<std::string>::iterator it3;
      for (it3 = data->dead_ids.begin(); it3 != data->dead_ids.end(); it3++) {
        if (*it3 == it2->node.node_id()) {
          it2->is_down = true;
        }
      }
      if (it2->is_down) {
        std::string dead_node;
        if (it2->node.SerialiseToString(&dead_node))
          downlist.push_back(dead_node);
          // args.add_downlist(dead_node);
      }
    }
    if (downlist.size() != 0) {
    // if (args.downlist_size() != 0) {
      // Send the downlist to the giver
      // TODO(Haiyang): restrict the parallel level to Alpha
      connect_to_node conn_type = CheckContactLocalAddress(it1->giver.node_id(),
          it1->giver.local_ip(), it1->giver.local_port(), it1->giver.host_ip());
      std::string contact_ip;
      boost::uint16_t contact_port;
      bool local;
      if (conn_type == LOCAL) {
        contact_ip = it1->giver.local_ip();
        contact_port = it1->giver.local_port();
        local = true;
      } else {
        contact_ip = it1->giver.host_ip();
        contact_port = it1->giver.host_port();
        local = false;
      }
      DownlistResponse *resp = new DownlistResponse();
      // rpcprotocol::Controller controller;
      google::protobuf::Closure *done = google::protobuf::NewCallback<
        DownlistResponse *> (&dummy_downlist_callback, resp);
      kadrpcs_.Downlist(downlist, contact_ip, contact_port, resp, done, local);
    }
  }
  data->downlist_sent = true;
  // End of downlist
}

void KNode::IterativeLookUp_SearchIteration(
    boost::shared_ptr<IterativeLookUpData> data) {
  // callback can only be called once
  if ((data->is_callbacked)||(!is_joined_ && data->method != BOOTSTRAP)) return;
  // sort the active contacts
  SortContactList(&data->active_contacts, data->key);
  // check whether thare are any closer nodes
  SortContactList(&data->short_list, data->key);
  bool no_more_closer_node = true;
  std::list<Contact>::iterator it;
  for (it = data->short_list.begin(); it != data->short_list.end(); ++it) {
    bool is_already_contacted = false;
    std::list<Contact>::iterator it1;
    for (it1 = data->already_contacted.begin();
      it1 != data->already_contacted.end(); ++it1) {
      if (*it == *it1) {
        is_already_contacted = true;
        break;
      }
    }
    if (!is_already_contacted) {
      no_more_closer_node = false;
      break;
    } else if (*it == data->pre_closest_node) {
      break;
    }
  }
  if (static_cast<int>(data->active_contacts.size()) > 0) {
    if (no_more_closer_node &&
        (data->pre_closest_node == data->active_contacts.front())) {
      // (static_cast<int>(data->active_probes.size()) == 0)
      // IterativeLookUp is done, prepare the result and call back
      IterativeLookUp_Callback(data);
      return;
    }
    data->pre_closest_node = data->active_contacts.front();
  }
  // already found a value, stop iteration
  if ((data->method == FIND_VALUE) && (data->find_value_result.size() > 0)) {
    IterativeLookUp_Callback(data);
    return;
  }
  // The search continues...
  // select alpha contacts for the search
  int contacted_now = 0;
  // std::list<Contact>::iterator it;
  for (it = data->short_list.begin(); it != data->short_list.end(); ++it) {
    // select contacts which haven't been contacted yet
    bool is_already_contacted = false;
    std::list<Contact>::iterator it1;
    for (it1 = data->already_contacted.begin();
      it1 != data->already_contacted.end(); ++it1) {
      if (*it == *it1) {
        is_already_contacted = true;
        break;
      }
    }
    if (!is_already_contacted) {
      Contact remote = *it;
      data->active_probes.push_back(remote);
      FindResponse *resp = new FindResponse();
      FindCallbackArgs callback_args(data);
      callback_args.sender = remote;
      // check if we send to local or remote address
      connect_to_node conn_type = CheckContactLocalAddress(remote.node_id(),
        remote.local_ip(), remote.local_port(), remote.host_ip());
      std::string contact_ip;
      boost::uint16_t contact_port;
      bool local;
      if (conn_type == LOCAL) {
        callback_args.retry = true;
        contact_ip = remote.local_ip();
        contact_port = remote.local_port();
        local = true;
      } else {
        contact_ip = remote.host_ip();
        contact_port = remote.host_port();
        local = false;
      }
      // send RPC to this contact
      google::protobuf::Closure *done = google::protobuf::NewCallback<
          KNode, const FindResponse*, FindCallbackArgs >(this,
          &KNode::IterativeLookUp_ExtendShortList, resp, callback_args);
      if (data->method == FIND_NODE || data->method == BOOTSTRAP) {
        if (data->method == BOOTSTRAP) {
          kad::Contact tmp_contact(node_id(), host_ip_, host_port_,
            local_host_ip_, local_host_port_, rv_ip_, rv_port_);
          std::string contact_str;
          tmp_contact.SerialiseToString(&contact_str);
          resp->set_requester_ext_addr(contact_str);
        } else if (data->key == remote.node_id()) {
            data->wait_for_key = true;
        }
        kadrpcs_.FindNode(data->key, contact_ip, contact_port, resp,
            done, local);
      } else if (data->method == FIND_VALUE) {
        kadrpcs_.FindValue(data->key, contact_ip, contact_port,
            resp, done, local);
      }
      // finished sending
      data->already_contacted.push_back(remote);
      ++contacted_now;
      if (contacted_now == alpha_) break;
    }
  }
  if (data->active_probes.size() == 0) {
    // No active probes were sent, there will be no any improvement, so we're
    // done.
    IterativeLookUp_Callback(data);
  } else if ((static_cast<int>(data->short_list.size()) < K_)&&
      (data->active_contacts.size() < data->short_list.size())) {
    // Schedule the next iteration if there are any active calls (Kademlia uses
    // loose parallelism).
    // Set the RPC request timeout
    // std::cout << "scheduling next iteration " << std::endl;
    // ptimer_->AddCallLater(kIterativeLookupDelay,
    //    boost::bind(&KNode::IterativeLookUp_SearchIteration, this, data));
  }
}

void KNode::IterativeLookUp(const std::string &key,
    const std::vector<Contact> &start_up_short_list,
    const remote_find_method &method,
    base::callback_func_type cb) {
  boost::shared_ptr<IterativeLookUpData> data(new IterativeLookUpData(method,
    key, cb));
  if (start_up_short_list.size() == 0) {  // get short list from routing table
    std::vector<Contact> close_nodes;
    std::vector<Contact> exclude_contacts;
    prouting_table_->FindCloseNodes(key, alpha_, &close_nodes,
        exclude_contacts);
    for (int i = 0; i < static_cast<int>(close_nodes.size()); ++i)
      data->short_list.push_back(close_nodes[i]);
  } else {  // use the start_up_short_list
    for (int i = 0; i < static_cast<int>(start_up_short_list.size()); ++i)
      data->short_list.push_back(start_up_short_list[i]);
  }
  // check whether the short_list is empty
  if (data->short_list.size() == 0) {
    CallbackWithFailure(cb);
    return;
  }
  IterativeLookUp_SearchIteration(data);
}

void KNode::StoreValue_IterativeStoreValue(const StoreResponse *response,
    StoreCallbackArgs callback_data) {
  if (!is_joined_) return;
  if (callback_data.data->is_callbacked) return;  // Only call back once

  if (response != NULL) {
    if (response->IsInitialized() &&
        response->has_node_id() &&
        response->node_id() != callback_data.sender.node_id()) {
      if (callback_data.retry) {
        delete response;
        StoreResponse *resp = new StoreResponse();
        UpdatePDRTContactToRemote(callback_data.sender.node_id());
        callback_data.retry = false;
      // send RPC to this contact's remote address because local failed
        google::protobuf::Closure *done1 = google::protobuf::NewCallback<
          KNode, const StoreResponse*, StoreCallbackArgs > (this,
          &KNode::StoreValue_IterativeStoreValue, resp, callback_data);
        kadrpcs_.Store(callback_data.data->key, callback_data.data->value,
          callback_data.data->pub_key, callback_data.data->sig_pub_key,
          callback_data.data->sig_req, callback_data.sender.host_ip(),
          callback_data.sender.host_port(), resp, done1, false);
        return;
      }
    }


    StoreResponse result_msg;
    if (response->IsInitialized()) {
      if (response->result() == kRpcResultSuccess) {
        ++callback_data.data->save_nodes;
      }
      AddContact(callback_data.sender);
    } else {
      // it has timeout
      RemoveContact(callback_data.sender.node_id());
    }
    // nodes has been contacted -- timeout, responded with failure or success
    ++callback_data.data->contacted_nodes;
    delete response;
  }
  if (callback_data.data->contacted_nodes >=
      static_cast<int>(callback_data.data->closest_nodes.size())) {
    // Finish storing
    StoreResponse store_value_result;
    std::string store_value_result_str;
    if (callback_data.data->save_nodes > 0)
      // Succeeded at least one value was stored
      store_value_result.set_result(kRpcResultSuccess);
    else
      // Failed
      store_value_result.set_result(kRpcResultFailure);
    store_value_result.SerializeToString(&store_value_result_str);
    callback_data.data->is_callbacked = true;
    callback_data.data->cb(store_value_result_str);
  } else {
    // Continues...
    // send RPC to this contact
    ++callback_data.data->index;
    if (callback_data.data->index >= static_cast<int>(
        callback_data.data->closest_nodes.size()))
      return;  // all requested were sent out, wait for the result
    Contact next_node = callback_data.data->closest_nodes[
        callback_data.data->index];
    StoreResponse *resp = new StoreResponse();
    StoreCallbackArgs callback_args(callback_data.data);
    callback_args.sender = next_node;

    connect_to_node conn_type = CheckContactLocalAddress(next_node.node_id(),
      next_node.local_ip(), next_node.local_port(), next_node.host_ip());
    std::string contact_ip;
    boost::uint16_t contact_port;
    bool local;
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = next_node.local_ip();
      contact_port = next_node.local_port();
      local = true;
    } else {
      contact_ip = next_node.host_ip();
      contact_port = next_node.host_port();
      local = false;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<
        KNode, const StoreResponse*, StoreCallbackArgs > (this,
        &KNode::StoreValue_IterativeStoreValue, resp, callback_args);
    kadrpcs_.Store(callback_data.data->key, callback_data.data->value,
        callback_data.data->pub_key, callback_data.data->sig_pub_key,
        callback_data.data->sig_req, contact_ip, contact_port,
        resp, done, local);
  }
}

void KNode::StoreValue_ExecuteStoreRPCs(const std::string& result,
    const std::string key, const std::string value, const std::string
    public_key, const std::string signed_public_key, const std::string
    signed_request, base::callback_func_type cb) {
  if (!is_joined_) return;
  // validate the result
  bool is_valid = true;
  FindResponse result_msg;
  if (!result_msg.ParseFromString(result)) {
    is_valid = false;
  } else if (result_msg.closest_nodes_size() == 0) {
    is_valid = false;
  }
  if ((is_valid)||(result_msg.result() == kRpcResultSuccess)) {
    std::vector<Contact> closest_nodes;
    for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
      Contact node;
      node.ParseFromString(result_msg.closest_nodes(i));
      closest_nodes.push_back(node);
    }
    if (closest_nodes.size() > 0) {
      if ((static_cast<int>(closest_nodes.size()) >= K_)&&(type_ != CLIENT)) {
        // If this node itself is closer to the key than the last (furtherest)
        // node in the returned list, store the value at this node as well.
        Contact furthest_contact = closest_nodes[closest_nodes.size()-1];
        if (kademlia_distance(node_id_, key) < (kademlia_distance(
            furthest_contact.node_id(), key))) {
          boost::uint32_t now = base::get_epoch_time();
          pdata_store_->StoreItem(key, value, now, now);
          closest_nodes.pop_back();
        }
      } else if (type_ != CLIENT) {
        boost::uint32_t now = base::get_epoch_time();
        pdata_store_->StoreItem(key, value, now, now);
      }
      boost::shared_ptr<IterativeStoreValueData>
        data(new struct IterativeStoreValueData(closest_nodes, key, value,
          cb, public_key, signed_public_key, signed_request));
      // decide the parallel level
      int parallel_size;
      if (static_cast<int>(data->closest_nodes.size())>alpha_)
        parallel_size = alpha_;
      else
        parallel_size = data->closest_nodes.size();
      for (int i = 0; i< parallel_size; ++i) {
        StoreCallbackArgs callback_args(data);
        StoreValue_IterativeStoreValue(NULL, callback_args);
      }
      return;
    }
    StoreResponse local_result;
    std::string local_result_str;
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  } else {
    CallbackWithFailure(cb);
  }
}

void KNode::StoreValue(const std::string &key, const std::string &value,
  const std::string &public_key, const std::string &signed_public_key,
  const std::string &signed_request, base::callback_func_type cb) {
  base::pd_scoped_lock guard(*pmutex_);

//  if (static_cast<int>(value.size()) > (transport::k_message_max*0.8)) {
//    TRI_LOG_STR("Value size is greater than what is supported.");
//    StoreResponse result;
//    std::string result_str;
//    result.set_result(kRpcResultFailure);
//    result.SerializeToString(&result_str);
//    cb(result_str);
//    return;
//  }
  FindCloseNodes(key, boost::bind(&KNode::StoreValue_ExecuteStoreRPCs, this,
      _1, key, value, public_key, signed_public_key, signed_request, cb));
}

void KNode::FindValue(const std::string &key, base::callback_func_type cb) {
  base::pd_scoped_lock guard(*pmutex_);
  std::vector<Contact> start_up_short_list;
  IterativeLookUp(key, start_up_short_list, FIND_VALUE, cb);
}

void KNode::FindNode_GetNode(const std::string& result,
    const std::string node_id, base::callback_func_type cb) {
  // validate the result
  bool is_valid = true;
  FindResponse result_msg;
  FindNodeResult find_node_result;
  std::string find_node_result_str;
  if (!result_msg.ParseFromString(result))
    is_valid = false;
  else if ((!result_msg.has_result())||
        (result_msg.closest_nodes_size() == 0)) {
      is_valid = false;
  }
  if ((is_valid)||(result_msg.result() == kRpcResultSuccess)) {
    for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
      Contact node;
      node.ParseFromString(result_msg.closest_nodes(i));
      if (node.node_id() == node_id) {
        find_node_result.set_result(kRpcResultSuccess);
        std::string node_str;
        node.SerialiseToString(&node_str);
        find_node_result.set_contact(node_str);
        find_node_result.SerializeToString(&find_node_result_str);
        cb(find_node_result_str);
        return;
      }
    }
  }
  // Failed to get any result
  find_node_result.set_result(kRpcResultFailure);
  find_node_result.SerializeToString(&find_node_result_str);
  cb(find_node_result_str);
}

void KNode::FindNode(const std::string &node_id, base::callback_func_type cb,
  const bool &local) {
  if (!local) {
    FindCloseNodes(node_id, boost::bind(&KNode::FindNode_GetNode, this, _1,
      node_id, cb));
  } else {
    FindNodeResult result;
    std::string ser_result;
    Contact contact;
    if (prouting_table_->GetContact(node_id, &contact)) {
      result.set_result(kRpcResultSuccess);
      std::string ser_contact;
      contact.SerialiseToString(&ser_contact);
      result.set_contact(ser_contact);
    } else {
      result.set_result(kRpcResultFailure);
    }
    result.SerializeToString(&ser_result);
    cb(ser_result);
  }
}

void KNode::FindCloseNodes(const std::string &node_id,
      base::callback_func_type cb) {
  base::pd_scoped_lock guard(*pmutex_);
  std::vector<Contact> start_up_short_list;
  IterativeLookUp(node_id, start_up_short_list, FIND_NODE, cb);
}

void KNode::Ping_HandleResult(const PingResponse *response,
      PingCallbackArgs callback_data) {
  if (!is_joined_) {
    delete response;
    return;
  }

  if (response->IsInitialized() &&
      response->has_node_id() &&
      response->node_id() != callback_data.sender.node_id()) {
    if (callback_data.retry) {
      delete response;
      PingResponse *resp = new PingResponse();
      UpdatePDRTContactToRemote(callback_data.sender.node_id());
      callback_data.retry = false;
      google::protobuf::Closure *done = google::protobuf::NewCallback<
          KNode, const PingResponse*, PingCallbackArgs > (this,
          &KNode::Ping_HandleResult, resp, callback_data);
      kadrpcs_.Ping(callback_data.sender.host_ip(),
          callback_data.sender.host_port(), resp, done, false);
      return;
    }
  }

  PingResponse result_msg;
  if (!response->IsInitialized()) {
    result_msg.set_result(kRpcResultFailure);
    RemoveContact(callback_data.sender.node_id());
  } else {
    result_msg = *response;
    if (response->result() == kRpcResultSuccess) {
      AddContact(callback_data.sender);
    } else {
      RemoveContact(callback_data.sender.node_id());
    }
  }
  std::string result_msg_str;
  result_msg.SerializeToString(&result_msg_str);
  callback_data.cb(result_msg_str);
  delete response;
}

void KNode::Ping_SendPing(const std::string& result,
      base::callback_func_type cb) {
  if (!is_joined_) return;
  FindNodeResult result_msg;
  if (result_msg.ParseFromString(result))
    if (result_msg.result() == kRpcResultSuccess) {
      Contact remote;
      if (remote.ParseFromString(result_msg.contact())) {
        Ping(remote, cb);
        return;
      }
    }
  // Failed to get any result
  PingResponse ping_result;
  std::string ping_result_str;
  ping_result.set_result(kRpcResultFailure);
  ping_result.SerializeToString(&ping_result_str);
  cb(ping_result_str);
}

void KNode::Ping(const std::string &node_id, base::callback_func_type cb) {
  base::pd_scoped_lock guard(*pmutex_);
  FindNode(node_id, boost::bind(&KNode::Ping_SendPing, this, _1, cb), false);
}

void KNode::Ping(const Contact &remote, base::callback_func_type cb) {
  if (!is_joined_) {
    PingResponse resp;
    resp.set_result(kRpcResultFailure);
    std::string ser_resp;
    resp.SerializeToString(&ser_resp);
    cb(ser_resp);
    return;
  } else {
    base::pd_scoped_lock guard(*pmutex_);
    PingResponse *resp = new PingResponse();
    PingCallbackArgs  callback_args(cb);
    callback_args.sender = remote;

    connect_to_node conn_type = CheckContactLocalAddress(remote.node_id(),
      remote.local_ip(), remote.local_port(), remote.host_ip());
    std::string contact_ip;
    boost::uint16_t contact_port;
    bool local;
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = remote.local_ip();
      contact_port = remote.local_port();
      local = true;
    } else {
      contact_ip = remote.host_ip();
      contact_port = remote.host_port();
      local = false;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<
        KNode, const PingResponse*, PingCallbackArgs > (this,
        &KNode::Ping_HandleResult, resp, callback_args);
    kadrpcs_.Ping(contact_ip, contact_port, resp, done, local);
  }
}

const std::string& KNode::node_id() const {
  if (type_ == CLIENT) {
    return fake_client_node_id_;
  } else {
    return node_id_;
  }
}

void KNode::AddContact(Contact new_contact, bool only_db) {
  if (new_contact.node_id() != "" &&
      new_contact.node_id() != client_node_id() &&
      new_contact.node_id() != node_id_) {
    if (!only_db) {
      new_contact.set_last_seen(base::get_epoch_milliseconds());
      prouting_table_->AddContact(new_contact);
    }

    // Adding to routing table db
    std::string remote_ip, rv_ip;
    remote_ip = base::inet_btoa(new_contact.host_ip());
    if (new_contact.rendezvous_ip() != "" )
      rv_ip = base::inet_btoa(new_contact.rendezvous_ip());
    base::PDRoutingTableTuple tuple(new_contact.node_id(),
                                    remote_ip,
                                    new_contact.host_port(),
                                    rv_ip,
                                    new_contact.rendezvous_port(),
                                    new_contact.node_id(),  // Publickey unknown
                                    0,
                                    0,
                                    0);
    routingtable_->AddTuple(tuple);
  }
}

void KNode::RemoveContact(const std::string &node_id) {
  Contact contact_to_delete;
  if (prouting_table_->GetContact(node_id, &contact_to_delete)) {
    // we won't delete bootstrapping nodes from the routing table
    bool is_bootstrap = false;
    for (int i = 0; i<static_cast<int>(bootstrapping_nodes_.size()); ++i) {
      if (bootstrapping_nodes_[i] == contact_to_delete) {
        is_bootstrap = true;
      }
    }
    if (!is_bootstrap)
      prouting_table_->RemoveContact(node_id, false);
  }
}

void KNode::FindKClosetNodes(const std::string &key, std::vector<Contact>
      *close_nodes, const std::vector<Contact> &exclude_contacts) {
  prouting_table_->FindCloseNodes(key, K_, close_nodes, exclude_contacts);
}

bool KNode::GetContact(const std::string &id, Contact *contact) {
  return prouting_table_->GetContact(id, contact);
}

void KNode::FindValueLocal(const std::string &key,
      std::vector<std::string> &values) {
  pdata_store_->LoadItem(key, values);
}

void KNode::StoreValueLocal(const std::string &key,
      const std::string &value) {
  boost::uint32_t now = base::get_epoch_time();
  pdata_store_->StoreItem(key, value, now, now);
}

ContactInfo KNode::contact_info() const {
  ContactInfo info;
  if (host_ip_.size() > 4) {
    info.set_ip(base::inet_atob(host_ip_));
  } else {
    info.set_ip(host_ip_);
  }
  if (local_host_ip_.size() > 4) {
    info.set_local_ip(base::inet_atob(local_host_ip_));
  } else {
    info.set_local_ip(local_host_ip_);
  }
  if (rv_ip_.size() > 4) {
    info.set_rv_ip(base::inet_atob(rv_ip_));
  } else {
    info.set_rv_ip(rv_ip_);
  }
  if (type_ == CLIENT) {
    info.set_node_id(fake_client_node_id_);
  } else {
    info.set_node_id(node_id_);
  }
  info.set_port(host_port_);
  info.set_local_port(local_host_port_);
  info.set_rv_port(rv_port_);
  return info;
}

void KNode::GetRandomContacts(
    const int &count,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *contacts) {
  // TODO(Jose): get the ones of same rank
  contacts->clear();
  std::vector<Contact> all_contacts;
  int kbuckets = prouting_table_->KbucketSize();
  for (int i = 0; i < kbuckets; ++i) {
    std::vector<kad::Contact> contacts_i;
    prouting_table_->GetContacts(i, &contacts_i, exclude_contacts);
    for (int j = 0; j < static_cast<int>(contacts_i.size()); ++j)
      all_contacts.push_back(contacts_i[j]);
  }
  if (static_cast<int>(all_contacts.size()) < count+1) {
    *contacts = all_contacts;
    return;
  }
  std::vector<Contact> temp_vector(count);
  // srand(rand() ^ static_cast<int>(base::get_epoch_time()));
  base::random_sample_n(all_contacts.begin(), all_contacts.end(),
    temp_vector.begin(), count);
  *contacts = temp_vector;
  return;
}

void KNode::HandleDeadRendezvousServer(const bool &dead_server,
    const std::string &ip, const uint16_t &port) {
  base::pd_scoped_lock guard(*pmutex_);
  if (dead_server) {
    Contact dead_contact("", ip, port);
    dead_rendezvous_server_ = dead_contact;
    Leave();
    Join(node_id_,
       kad_config_path_.string(),
       boost::bind(&KNode::ReBootstrapping_Callback, this, _1));
  }
}

void KNode::ReBootstrapping_Callback(const std::string &result) {
  base::GeneralResponse local_result;
  if (!local_result.ParseFromString(result) ||
      local_result.result() == kRpcResultFailure) {
    // TODO(David): who should we inform if after trying to bootstrap again
    // because the rendezvous server died, the bootstrap operation fails?
    is_joined_ = false;
  } else {
    is_joined_ = true;
  }
}

void KNode::RegisterKadService() {
  boost::shared_ptr<KadService> remote_service_(new KadService(this));
  premote_service_ = remote_service_;
  boost::shared_ptr<rpcprotocol::Channel>
      svc_channel_(new rpcprotocol::Channel(pchannel_manager_->ptransport(),
                                            pchannel_manager_.get()));
  pservice_channel_ = svc_channel_;
  pservice_channel_->SetService(premote_service_.get());
  pchannel_manager_->RegisterChannel(
      premote_service_->GetDescriptor()->name(), pservice_channel_.get());
}

void KNode::UnRegisterKadService() {
  pchannel_manager_->UnRegisterChannel(
    premote_service_->GetDescriptor()->name());
  pservice_channel_.reset();
  premote_service_.reset();
}

connect_to_node KNode::CheckContactLocalAddress(const std::string &id,
    const std::string &ip, const uint16_t &port, const std::string &ext_ip) {
  int result = routingtable_->ContactLocal(id);
  connect_to_node conn_type;
  std::string ext_ip_dec;
  switch (result) {
    case LOCAL: conn_type = LOCAL;
                break;
    case REMOTE: conn_type = REMOTE;
                 break;
    case UNKNOWN: ext_ip_dec = base::inet_btoa(ext_ip);
                  if (host_ip_ != ext_ip_dec) {
                    conn_type = REMOTE;
                  } else if (pchannel_manager_->CheckConnection(ip, port)) {
                    conn_type = LOCAL;
                  } else {
                    conn_type = REMOTE;
                  }
                  routingtable_->UpdateContactLocal(id,
                    static_cast<int>(conn_type));
                  break;
  }
  return conn_type;
}

void KNode::OnUPnPPortMapping(int, int port,
    std::string const& errmsg, int) {
  base::pd_scoped_lock guard(*pmutex_);
  if (errmsg == "") {
#ifdef DEBUG
    printf("UPnP port mapped: %d\n", port);
#endif
    upnp_mapped_port_ = port;
    upnp_started_ = true;
  } else {
#ifdef DEBUG
    printf("Error occurred when trying to map UPnP Port: %s\n", errmsg.c_str());
#endif
  }
}

void KNode::UPnPMap(boost::uint16_t host_port) {
  // Get a UPnP mapping port
  upnp_half_open_ = new libtorrent::connection_queue(upnp_ios_);
#ifdef WIN32
  // windows XP has a limit on the number of
  // simultaneous half-open TCP connections
  DWORD windows_version = ::GetVersion();
  if ((windows_version & 0xff) >= 6) {
    // on vista the limit is 5 (in home edition)
    upnp_half_open_->limit(4);
  } else {
    // on XP SP2 it's 10
    upnp_half_open_->limit(8);
  }
#endif
  boost::asio::deadline_timer timer(upnp_ios_);
  upnp_user_agent_ = "maidsafe";
  upnp_mapped_port_ = 0;
  upnp_ = new libtorrent::upnp(upnp_ios_,
                               *upnp_half_open_,
                               libtorrent::address_v4(),
                               upnp_user_agent_,
                               boost::bind(&KNode::OnUPnPPortMapping,
                                           this,
                                           _1,
                                           _2,
                                           _3,
                                           1),
                               false);
  printf("Discovering the UPnP device...\n");
  upnp_->discover_device();
  timer.expires_from_now(boost::posix_time::seconds(3));
  timer.async_wait(boost::bind(&libtorrent::io_service::stop,
                               boost::ref(upnp_ios_)));
  upnp_ios_.reset();
  upnp_ios_.run();
  printf("Mapping UPnP port...\n");
  upnp_udp_map_ = upnp_->add_mapping(libtorrent::upnp::udp,
                                     host_port,
                                     host_port);
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&libtorrent::io_service::stop,
                               boost::ref(upnp_ios_)));
  upnp_ios_.reset();
  upnp_ios_.run();
}

void KNode::UnMapUPnP() {
  {
    base::pd_scoped_lock guard(*pmutex_);
    upnp_started_ = false;
    upnp_mapped_port_ = 0;
  }
  boost::asio::deadline_timer timer(upnp_ios_);
#ifdef DEBUG
  printf("Deleting the UPnP mapped port...\n");
#endif
  upnp_->delete_mapping(upnp_udp_map_);
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&libtorrent::io_service::stop,
                                boost::ref(upnp_ios_)));
  upnp_ios_.reset();
  upnp_ios_.run();
#ifdef DEBUG
  printf("Closing UPnP...\n");
#endif
  upnp_->close();
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&libtorrent::io_service::stop,
                                boost::ref(upnp_ios_)));
  upnp_ios_.reset();
  upnp_ios_.run();
  delete upnp_half_open_;
}

void KNode::UpdatePDRTContactToRemote(const std::string &node_id) {
  routingtable_->UpdateContactLocal(node_id, static_cast<int>(REMOTE));
}
}  // namespace kad
