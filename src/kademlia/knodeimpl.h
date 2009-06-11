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

//  #define VERBOSE_DEBUG
//  #define SHOW_MUTEX

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
#include "base/routingtable.h"
#include "kademlia/datastore.h"
#include "kademlia/kadrpc.h"
#include "kademlia/routingtable.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service.pb.h"
#include "upnp/upnp.hpp"

namespace kad {
class KadService;

class ContactInfo;

void SortContactList(std::list<Contact> *contact_list,
                     const std::string &target_key);

inline void dummy_callback(const std::string&) {}

inline void dummy_downlist_callback(DownlistResponse *response) {
  delete response;
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
struct IterativeLookUpData {
  IterativeLookUpData(const remote_find_method &method,
                      const std::string &key,
                      base::callback_func_type cb)
                          : method(method),
                            short_list(),
                            key(key),
                            find_value_result(),
                            pre_closest_node(),
                            active_probes(),
                            already_contacted(),
                            active_contacts(),
                            dead_ids(),
                            downlist(),
                            active_probes_after_callback(0),
                            downlist_sent(false),
                            is_callbacked(false),
                            wait_for_key(false),
                            cb(cb) {}
  remote_find_method method;
  std::list<Contact> short_list;
  std::string key;
  std::list<std::string> find_value_result;
  Contact pre_closest_node;
  std::list<Contact> active_probes;
  std::list<Contact> already_contacted;
  std::list<Contact> active_contacts;
  std::list<std::string> dead_ids;
  std::list<struct DownListData> downlist;
  int active_probes_after_callback;
  bool downlist_sent;
  bool is_callbacked;
  bool wait_for_key;
  base::callback_func_type cb;
};

struct IterativeStoreValueData {
    IterativeStoreValueData(const std::vector<Contact> &close_nodes,
                            const std::string &key,
                            const std::string &value,
                            base::callback_func_type cb,
                            const std::string &pubkey,
                            const std::string &sigpubkey,
                            const std::string &sigreq)
                                : closest_nodes(close_nodes),
                                  key(key),
                                  value(value),
                                  save_nodes(0),
                                  contacted_nodes(0),
                                  index(-1),
                                  cb(cb),
                                  is_callbacked(false),
                                  data_type(0),
                                  pub_key(pubkey),
                                  sig_pub_key(sigpubkey),
                                  sig_req(sigreq) {}
  std::vector<Contact> closest_nodes;
  std::string key;
  std::string value;
  int save_nodes;
  int contacted_nodes;
  int index;
  base::callback_func_type cb;
  bool is_callbacked;
  int data_type;
  std::string pub_key;
  std::string sig_pub_key;
  std::string sig_req;
};

struct FindCallbackArgs {
    explicit FindCallbackArgs(boost::shared_ptr<IterativeLookUpData> data)
        : sender(), data(data), retry(false) {}
  Contact sender;
  boost::shared_ptr<IterativeLookUpData> data;
  bool retry;
};

struct StoreCallbackArgs {
    explicit StoreCallbackArgs(boost::shared_ptr<IterativeStoreValueData> data)
        : sender(), data(data), retry(false) {}
  Contact sender;
  boost::shared_ptr<IterativeStoreValueData> data;
  bool retry;
};

struct PingCallbackArgs {
  explicit PingCallbackArgs(base::callback_func_type cb)
      : sender(), cb(cb), retry(false) {}
  Contact sender;
  base::callback_func_type cb;
  bool retry;
};

struct BootstrapData {
  base::callback_func_type cb;
  std::string bootstrap_ip;
  boost::uint16_t bootstrap_port;
};

struct BootstrapArgs {
  BootstrapArgs(): cached_nodes(),
                   cb(),
                   active_process(0),
                   is_callbacked(false),
                   port_fw(false) {}
  std::vector<Contact> cached_nodes;
  base::callback_func_type cb;
  int active_process;
  bool is_callbacked, port_fw;
};

class KNodeImpl {
 public:
  KNodeImpl(const std::string &datastore_dir,
            boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
            node_type type);
  // constructor used to set up parameters k, alpha, and beta for kademlia
  KNodeImpl(const std::string &datastore_dir,
            boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
            node_type type,
            const boost::uint16_t k,
            const int &alpha,
            const int &beta);
  ~KNodeImpl();
  // if node_id is "", it will be randomly generated
  void Join(const std::string &node_id,
            const std::string &kad_config_file,
            base::callback_func_type cb,
            const bool &port_forwarded);
  void Leave();
  void StoreValue(const std::string &key,
                  const std::string &value,
                  const std::string &public_key,
                  const std::string &signed_public_key,
                  const std::string &signed_request,
                  base::callback_func_type cb);
  void FindValue(const std::string &key, base::callback_func_type cb);
  void FindNode(const std::string &node_id,
                base::callback_func_type cb,
                const bool &local);
  void FindCloseNodes(const std::string &node_id,
                      base::callback_func_type cb);
  void FindKClosestNodes(const std::string &key,
                         std::vector<Contact> *close_nodes,
                         const std::vector<Contact> &exclude_contacts);
  void Ping(const std::string &node_id, base::callback_func_type cb);
  void Ping(const Contact &remote, base::callback_func_type cb);
  int AddContact(Contact new_contact, bool only_db);
  void RemoveContact(const std::string &node_id);
  bool GetContact(const std::string &id, Contact *contact);
  void FindValueLocal(const std::string &key,
                      std::vector<std::string> &values);
  void StoreValueLocal(const std::string &key,
                       const std::string &value);
  void GetRandomContacts(const int &count,
                         const std::vector<Contact> &exclude_contacts,
                         std::vector<Contact> *contacts);
  void HandleDeadRendezvousServer(const bool &dead_server,
                                  const std::string &ip,
                                  const uint16_t &port);
  connect_to_node CheckContactLocalAddress(const std::string &id,
                                           const std::string &ip,
                                           const uint16_t &port,
                                           const std::string &ext_ip);
  void UpdatePDRTContactToRemote(const std::string &node_id);
  ContactInfo contact_info() const;
  void CheckToInsert(const Contact &new_contact);
  inline std::string node_id() const {
    return (type_ == CLIENT) ? fake_client_node_id_ : node_id_;
  }
  inline std::string host_ip() const { return host_ip_; }
  inline boost::uint16_t host_port() const { return host_port_; }
  inline std::string local_host_ip() const { return local_host_ip_; }
  inline boost::uint16_t local_host_port() const { return local_host_port_; }
  inline std::string rv_ip() const { return rv_ip_; }
  inline boost::uint16_t rv_port() const { return rv_port_; }
  inline bool is_joined() const { return is_joined_; }
  inline KadRpcs* kadrpcs() { return &kadrpcs_; }
  friend class KadServicesTest;
  friend class NatDetectionTest;
 private:
  KNodeImpl &operator=(const KNodeImpl&);
  KNodeImpl(const KNodeImpl&);
  inline void CallbackWithFailure(base::callback_func_type cb);
  void Bootstrap_Callback(const boost::shared_ptr<BootstrapResponse> response,
                          BootstrapData data);
  void Bootstrap(const std::string &bootstrap_ip,
                 const boost::uint16_t &bootstrap_port,
                 base::callback_func_type cb,
                 const bool &port_forwarded);
  void Join_Bootstrapping_Iteration_Client(
      const std::string& result,
      boost::shared_ptr<struct BootstrapArgs> args,
      const std::string bootstrap_ip,
      const boost::uint16_t bootstrap_port,
      const std::string local_bs_ip,
      const boost::uint16_t local_bs_port);
  void Join_Bootstrapping_Iteration(
      const std::string& result,
      boost::shared_ptr<struct BootstrapArgs> args,
      const std::string bootstrap_ip,
      const boost::uint16_t bootstrap_port,
      const std::string local_bs_ip,
      const boost::uint16_t local_bs_port);
  void Join_Bootstrapping(base::callback_func_type cb,
                          std::vector<Contact> &cached_nodes,
                          const bool &port_forwarded);
  void Join_RefreshNode(base::callback_func_type cb,
                        const bool &port_forwarded);
  void SaveBootstrapContacts();  // save the routing table into .kadconfig file
  int LoadBootstrapContacts();
  void RefreshRoutine();
  void IterativeLookUp_CancelActiveProbe(
      Contact sender,
      boost::shared_ptr<IterativeLookUpData> data);
  void IterativeLookUp_ExtendShortList(const FindResponse *response,
                                       FindCallbackArgs callback_data);
  void IterativeLookUp_Callback(boost::shared_ptr<IterativeLookUpData> data);
  void IterativeLookUp_SendDownlist(
      boost::shared_ptr<IterativeLookUpData> data);
  void IterativeLookUp_SearchIteration(
      boost::shared_ptr<IterativeLookUpData> data);
  void IterativeLookUp(const std::string &key,
                       const std::vector<Contact> &start_up_short_list,
                       const remote_find_method &method,
                       base::callback_func_type cb);
  void StoreValue_IterativeStoreValue(const StoreResponse *response,
                                      StoreCallbackArgs callback_args);
  void StoreValue_ExecuteStoreRPCs(const std::string &result,
                                   const std::string &key,
                                   const std::string &value,
                                   const std::string &public_key,
                                   const std::string &signed_public_key,
                                   const std::string &signed_request,
                                   base::callback_func_type cb);
  void FindNode_GetNode(const std::string &result,
                        const std::string &node_id,
                        base::callback_func_type cb);
  void Ping_HandleResult(const PingResponse *response,
                         PingCallbackArgs callback_data);
  void Ping_SendPing(const std::string& result, base::callback_func_type cb);
  void ReBootstrapping_Callback(const std::string &result);
  void RegisterKadService();
  void UnRegisterKadService();
  void OnUPnPPortMapping(int mapping,
                         int port,
                         std::string const& errmsg,
                         int map_transport);
  void UPnPMap(boost::uint16_t host_port);
  void UnMapUPnP();
  void CheckToInsert_Callback(const std::string &result, std::string id,
      Contact new_contact);
  boost::mutex routingtable_mutex_;
  boost::mutex kadconfig_mutex_;
  boost::mutex extendshortlist_mutex_;
  boost::mutex joinbootstrapping_mutex_;
  boost::mutex leave_mutex_;
  boost::mutex activeprobes_mutex_;
  boost::shared_ptr<base::CallLaterTimer> ptimer_;
  boost::shared_ptr<rpcprotocol::ChannelManager> pchannel_manager_;
  boost::shared_ptr<rpcprotocol::Channel> pservice_channel_;
  boost::shared_ptr<DataStore> pdata_store_;
  boost::shared_ptr<KadService> premote_service_;
  KadRpcs kadrpcs_;
  volatile bool is_joined_;
  boost::shared_ptr<RoutingTable> prouting_table_;
  std::string node_id_;
  std::string host_ip_;
  std::string fake_client_node_id_;
  node_type type_;
  boost::uint16_t host_port_;
  std::string rv_ip_;
  boost::uint16_t rv_port_;
  std::vector<Contact> bootstrapping_nodes_;
  const boost::uint16_t K_;
  int alpha_, beta_;
  bool refresh_routine_started_;
  boost::filesystem::path kad_config_path_;
  boost::shared_ptr<base::PDRoutingTableHandler> routingtable_;
  std::string local_host_ip_;
  boost::uint16_t local_host_port_;
  bool stopping_;
  // for UPnP
  bool upnp_started_;
  libtorrent::io_service upnp_ios_;
  boost::intrusive_ptr<libtorrent::upnp> upnp_;
  libtorrent::connection_queue *upnp_half_open_;
  std::string upnp_user_agent_;
  int upnp_mapped_port_;
  int upnp_udp_map_;
};
}  // namespace kad
#endif  // KADEMLIA_KNODEIMPL_H_
