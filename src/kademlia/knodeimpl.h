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

#ifndef KADEMLIA_KNODEIMPL_H_
#define KADEMLIA_KNODEIMPL_H_

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <gtest/gtest_prod.h>

#include <string>
#include <vector>
#include <list>
#include <map>
#include <memory>

#include "base/calllatertimer.h"
#include "base/config.h"
#include "base/singleton.h"
#include "kademlia/datastore.h"
#include "kademlia/kadrpc.h"
#include "kademlia/natrpc.h"
#include "kademlia/routingtable.h"
#include "kademlia/kadservice.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/channel-api.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service.pb.h"
#include "upnp/upnpclient.h"
#include "maidsafe/transporthandler-api.h"

namespace kad {
class ContactInfo;

struct LookupContact;

void SortContactList(std::list<Contact> *contact_list,
    const KadId &target_key);

void SortLookupContact(std::list<LookupContact> *contact_list,
    const KadId &target_key);

inline void dummy_callback(const std::string&) {}

inline void dummy_downlist_callback(DownlistResponse *response,
    rpcprotocol::Controller *ctrler) {
  delete response;
  delete ctrler;
}

struct DownListCandidate {
  DownListCandidate() : node(), is_down(false) {}
  Contact node;
  bool is_down;  // flag to mark whether this node is down
};

// mapping of giver and suggested list of entires
struct DownListData {
  DownListData() : giver(), candidate_list() {}
  Contact giver;
  std::list<struct DownListCandidate> candidate_list;
};

// define data structures for callbacks
struct LookupContact {
  LookupContact() : kad_contact(), contacted(false) {}
  Contact kad_contact;
  bool contacted;
};

struct IterativeLookUpData {
  IterativeLookUpData(const remote_find_method &method,
      const KadId &key, base::callback_func_type cb)
      : method(method), key(key), short_list(), current_alpha(),
        active_contacts(), active_probes(),
        values_found(), dead_ids(), downlist(), downlist_sent(false),
        in_final_iteration(false), is_callbacked(false), wait_for_key(false),
        cb(cb), alternative_value_holder(), sig_values_found() {}
  remote_find_method method;
  KadId key;
  std::list<LookupContact> short_list;
  std::list<Contact> current_alpha, active_contacts, active_probes;
  std::list<std::string> values_found, dead_ids;
  std::list<struct DownListData> downlist;
  bool downlist_sent, in_final_iteration, is_callbacked, wait_for_key;
  base::callback_func_type cb;
  ContactInfo alternative_value_holder;
  std::list<kad::SignedValue> sig_values_found;
};

struct IterativeStoreValueData {
  IterativeStoreValueData(const std::vector<Contact> &close_nodes,
      const KadId &key, const std::string &value,
      base::callback_func_type cb, const bool &publish_val,
      const boost::int32_t &timetolive, const SignedValue &svalue,
      const SignedRequest &sreq) : closest_nodes(close_nodes), key(key),
        value(value), save_nodes(0), contacted_nodes(0), index(-1), cb(cb),
        is_callbacked(false), data_type(0), publish(publish_val),
        ttl(timetolive), sig_value(svalue), sig_request(sreq) {}
  IterativeStoreValueData(const std::vector<Contact> &close_nodes,
      const KadId &key, const std::string &value,
      base::callback_func_type cb, const bool &publish_val,
      const boost::uint32_t &timetolive)
      : closest_nodes(close_nodes), key(key),
        value(value), save_nodes(0), contacted_nodes(0), index(-1), cb(cb),
        is_callbacked(false), data_type(0), publish(publish_val),
        ttl(timetolive), sig_value(), sig_request() {}
  std::vector<Contact> closest_nodes;
  KadId key;
  std::string value;
  boost::uint32_t save_nodes, contacted_nodes, index;
  base::callback_func_type cb;
  bool is_callbacked;
  int data_type;
  bool publish;
  boost::int32_t ttl;
  SignedValue sig_value;
  SignedRequest sig_request;
};

struct IterativeDelValueData {
  IterativeDelValueData(const std::vector<Contact> &close_nodes,
      const KadId &key, const SignedValue &svalue,
      const SignedRequest &sreq, base::callback_func_type cb)
      : closest_nodes(close_nodes), key(key), del_nodes(0), contacted_nodes(0),
        index(-1), cb(cb), is_callbacked(false), value(svalue),
        sig_request(sreq) {}
  std::vector<Contact> closest_nodes;
  KadId key;
  boost::uint32_t del_nodes, contacted_nodes, index;
  base::callback_func_type cb;
  bool is_callbacked;
  SignedValue value;
  SignedRequest sig_request;
};

struct FindCallbackArgs {
  explicit FindCallbackArgs(boost::shared_ptr<IterativeLookUpData> data)
      : remote_ctc(), data(data), retry(false), rpc_ctrler(NULL) {}
  Contact remote_ctc;
  boost::shared_ptr<IterativeLookUpData> data;
  bool retry;
  rpcprotocol::Controller *rpc_ctrler;
};

struct StoreCallbackArgs {
  explicit StoreCallbackArgs(boost::shared_ptr<IterativeStoreValueData> data)
      : remote_ctc(), data(data), retry(false), rpc_ctrler(NULL) {}
  Contact remote_ctc;
  boost::shared_ptr<IterativeStoreValueData> data;
  bool retry;
  rpcprotocol::Controller *rpc_ctrler;
};

struct PingCallbackArgs {
  explicit PingCallbackArgs(base::callback_func_type cb)
      : remote_ctc(), cb(cb), retry(false), rpc_ctrler(NULL) {}
  Contact remote_ctc;
  base::callback_func_type cb;
  bool retry;
  rpcprotocol::Controller *rpc_ctrler;
};

struct DeleteCallbackArgs {
  explicit DeleteCallbackArgs(boost::shared_ptr<IterativeDelValueData> data)
      : remote_ctc(), data(data), retry(false), rpc_ctrler(NULL) {}
  Contact remote_ctc;
  boost::shared_ptr<IterativeDelValueData> data;
  bool retry;
  rpcprotocol::Controller *rpc_ctrler;
};

struct BootstrapData {
  base::callback_func_type cb;
  std::string bootstrap_ip;
  boost::uint16_t bootstrap_port;
  rpcprotocol::Controller *rpc_ctrler;
};

struct BootstrapArgs {
  BootstrapArgs() : cached_nodes(), cb(), active_process(0),
      is_callbacked(false), dir_connected(false) {}
  std::vector<Contact> cached_nodes;
  base::callback_func_type cb;
  boost::uint16_t active_process;
  bool is_callbacked, dir_connected;
};

class KNodeImpl {
 public:
  KNodeImpl(rpcprotocol::ChannelManager* channel_manager,
      transport::TransportHandler *ptrans_handler, node_type type,
      const std::string &private_key, const std::string &public_key,
      const bool &port_forwarded, const bool &use_upnp);
  // constructor used to set up parameters k, alpha, and beta for kademlia
  KNodeImpl(rpcprotocol::ChannelManager *channel_manager,
      transport::TransportHandler *ptrans_handler, node_type type,
      const boost::uint16_t &k, const boost::uint16_t &alpha,
      const boost::uint16_t &beta, const boost::uint32_t &refresh_time,
      const std::string &private_key, const std::string &public_key,
      const bool &port_forwarded, const bool &use_upnp);
  ~KNodeImpl();

  void SetTransID(boost::int16_t t) { trans_id_ = t; }

  void Join(const KadId &node_id, const std::string &kad_config_file,
      base::callback_func_type cb);
  void Join(const std::string &kad_config_file, base::callback_func_type cb);

  // Use this join for the first node in the network
  void Join(const KadId &node_id, const std::string &kad_config_file,
      const std::string &external_ip, const boost::uint16_t &external_port,
      base::callback_func_type cb);
  void Join(const std::string &kad_config_file, const std::string &external_ip,
      const boost::uint16_t &external_port, base::callback_func_type cb);

  void Leave();
  void StoreValue(const KadId &key, const SignedValue &value,
      const SignedRequest &sreq, const boost::int32_t &ttl,
      base::callback_func_type cb);
  void StoreValue(const KadId &key, const std::string &value,
      const boost::int32_t &ttl, base::callback_func_type cb);
  void DeleteValue(const KadId &key, const SignedValue &value,
      const SignedRequest &request, base::callback_func_type cb);
  void FindValue(const KadId &key, const bool &check_alt_store,
      base::callback_func_type cb);
  void FindNode(const KadId &node_id, base::callback_func_type cb,
      const bool &local);
  void FindCloseNodes(const KadId &node_id, base::callback_func_type cb);
  void FindKClosestNodes(const KadId &key,
      std::vector<Contact> *close_nodes,
      const std::vector<Contact> &exclude_contacts);
  void Ping(const KadId &node_id, base::callback_func_type cb);
  void Ping(const Contact &remote, base::callback_func_type cb);
  int AddContact(Contact new_contact, const float & rtt, const bool &only_db);
  void RemoveContact(const KadId &node_id);
  bool GetContact(const KadId &id, Contact *contact);
  bool FindValueLocal(const KadId &key, std::vector<std::string> *values);
  bool StoreValueLocal(const KadId &key, const std::string &value,
      const boost::int32_t &ttl);
  bool RefreshValueLocal(const KadId &key, const std::string &value,
      const boost::int32_t &ttl);
  bool DelValueLocal(const KadId &key, const SignedValue &value,
      const SignedRequest &req);
  void GetRandomContacts(const boost::uint16_t &count,
      const std::vector<Contact> &exclude_contacts,
      std::vector<Contact> *contacts);
  void HandleDeadRendezvousServer(const bool &dead_server);
  connect_to_node CheckContactLocalAddress(const KadId &id,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &ext_ip);
  void UpdatePDRTContactToRemote(const KadId &node_id,
                                 const std::string &host_ip);
  ContactInfo contact_info() const;
  inline KadId node_id() const {
    return (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED)
        ? fake_client_node_id_ : node_id_;
  }
  boost::uint32_t KeyLastRefreshTime(const KadId &key,
      const std::string &value);
  boost::uint32_t KeyExpireTime(const KadId &key,
      const std::string &value);
  inline std::string host_ip() const { return host_ip_; }
  inline boost::uint16_t host_port() const { return host_port_; }
  inline std::string local_host_ip() const { return local_host_ip_; }
  inline boost::uint16_t local_host_port() const { return local_host_port_; }
  inline std::string rv_ip() const { return rv_ip_; }
  inline boost::uint16_t rv_port() const { return rv_port_; }
  inline bool is_joined() const { return is_joined_; }
  inline KadRpcs* kadrpcs() { return &kadrpcs_; }
  bool HasRSAKeys();
  boost::int32_t KeyValueTTL(const KadId &key,
      const std::string &value) const;
  inline void SetAlternativeStore(base::AlternativeStore* alt_store) {
    alternative_store_ = alt_store;
    if (premote_service_.get() != NULL)
      premote_service_->set_alternative_store(alternative_store_);
  }
  inline base::AlternativeStore *alternative_store() {
    return alternative_store_;
  }
  inline void set_signature_validator(base::SignatureValidator *validator) {
    signature_validator_ = validator;
    if (premote_service_ != 0)
      premote_service_->set_signature_validator(signature_validator_);
  }
  inline nat_type host_nat_type() {
    return host_nat_type_;
  }
 private:
  KNodeImpl &operator=(const KNodeImpl&);
  KNodeImpl(const KNodeImpl&);
  inline void CallbackWithFailure(base::callback_func_type cb);
  void Bootstrap_Callback(const BootstrapResponse *response,
      BootstrapData data);
  void Bootstrap(const std::string &bootstrap_ip,
      const boost::uint16_t &bootstrap_port, base::callback_func_type cb,
      const bool &dir_connected);
  void Join_Bootstrapping_Iteration_Client(const std::string& result,
      boost::shared_ptr<struct BootstrapArgs> args,
      const std::string bootstrap_ip, const boost::uint16_t bootstrap_port,
      const std::string local_bs_ip, const boost::uint16_t local_bs_port);
  void Join_Bootstrapping_Iteration(const std::string& result,
      boost::shared_ptr<struct BootstrapArgs> args,
      const std::string bootstrap_ip, const boost::uint16_t bootstrap_port,
      const std::string local_bs_ip, const boost::uint16_t local_bs_port);
  void Join_Bootstrapping(base::callback_func_type cb,
      std::vector<Contact> &cached_nodes, const bool &got_external_address);
  void Join_RefreshNode(base::callback_func_type cb,
      const bool &port_forwarded);
  void SaveBootstrapContacts();  // save the routing table into .kadconfig file
  boost::int16_t LoadBootstrapContacts();
  void RefreshRoutine();
  void StartSearchIteration(const KadId &key,
      const remote_find_method &method, base::callback_func_type cb);
  void SearchIteration_ExtendShortList(const FindResponse *response,
      FindCallbackArgs callback_data);
  void SearchIteration(boost::shared_ptr<IterativeLookUpData> data);
  void FinalIteration(boost::shared_ptr<IterativeLookUpData> data);
  void SendDownlist(boost::shared_ptr<IterativeLookUpData> data);
  void SendFindRpc(Contact remote, boost::shared_ptr<IterativeLookUpData> data,
      const connect_to_node &conn_type);
  void SearchIteration_CancelActiveProbe(Contact sender,
      boost::shared_ptr<IterativeLookUpData> data);
  void SearchIteration_Callback(boost::shared_ptr<IterativeLookUpData> data);
  void SendFinalIteration(boost::shared_ptr<IterativeLookUpData> data);
  void StoreValue_IterativeStoreValue(const StoreResponse *response,
      StoreCallbackArgs callback_data);
  void StoreValue_ExecuteStoreRPCs(const std::string &result,
      const KadId &key, const std::string &value,
      const SignedValue &sig_value, const SignedRequest &sig_req,
      const bool &publish,
      const boost::int32_t &ttl, base::callback_func_type cb);
  void DelValue_ExecuteDeleteRPCs(const std::string &result,
      const KadId &key, const SignedValue &value,
      const SignedRequest &sig_req, base::callback_func_type cb);
  void DelValue_IterativeDeleteValue(const DeleteResponse *response,
      DeleteCallbackArgs callback_data);
  void FindNode_GetNode(const std::string &result, const KadId &node_id,
      base::callback_func_type cb);
  void Ping_HandleResult(const PingResponse *response,
      PingCallbackArgs callback_data);
  void Ping_SendPing(const std::string& result, base::callback_func_type cb);
  void ReBootstrapping_Callback(const std::string &result);
  void RegisterKadService();
  void UnRegisterKadService();
  void UPnPMap(boost::uint16_t host_port);
  void UnMapUPnP();
  void CheckToInsert(const Contact &new_contact);
  void CheckToInsert_Callback(const std::string &result, KadId id,
      Contact new_contact);
  void CheckAddContacts();
  void RefreshValuesRoutine();
  void RefreshValue(const KadId &key, const std::string &value,
      const boost::int32_t &ttl, base::callback_func_type cb);
  void RefreshValueCallback(const std::string &result, const KadId &key,
      const std::string &value, const boost::int32_t &ttl,
      boost::shared_ptr<boost::uint32_t> refreshes_done,
      const boost::uint32_t &total_refreshes);
  boost::mutex routingtable_mutex_, kadconfig_mutex_, extendshortlist_mutex_,
      joinbootstrapping_mutex_, leave_mutex_, activeprobes_mutex_,
      pendingcts_mutex_;
  boost::shared_ptr<base::CallLaterTimer> ptimer_;
  rpcprotocol::ChannelManager *pchannel_manager_;
  transport::TransportHandler *ptrans_handler_;
  boost::int16_t trans_id_;
  boost::shared_ptr<rpcprotocol::Channel> pservice_channel_;
  boost::shared_ptr<DataStore> pdata_store_;
  base::AlternativeStore *alternative_store_;
  boost::shared_ptr<KadService> premote_service_;
  KadRpcs kadrpcs_;
  NatRpcs natrpcs_;
  volatile bool is_joined_;
  boost::shared_ptr<RoutingTable> prouting_table_;
  KadId node_id_, fake_client_node_id_;
  std::string host_ip_;
  node_type type_;
  boost::uint16_t host_port_;
  std::string rv_ip_;
  boost::uint16_t rv_port_;
  std::vector<Contact> bootstrapping_nodes_;
  const boost::uint16_t K_, alpha_, beta_;
  bool refresh_routine_started_;
  boost::filesystem::path kad_config_path_;
  std::string local_host_ip_;
  boost::uint16_t local_host_port_;
  bool stopping_, port_forwarded_, use_upnp_;
  std::list<Contact> contacts_to_add_;
  boost::shared_ptr<boost::thread> addcontacts_routine_;
  boost::condition_variable add_ctc_cond_;
  std::string private_key_, public_key_;
  nat_type host_nat_type_;
  // for UPnP
  upnp::UpnpIgdClient upnp_;
  boost::uint16_t upnp_mapped_port_;
  //
  base::SignatureValidator *signature_validator_;
};
}  // namespace kad
#endif  // KADEMLIA_KNODEIMPL_H_
