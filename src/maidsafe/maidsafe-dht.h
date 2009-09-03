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

/*******************************************************************************
 * This is the API for maidsafe-dht and is the only program access for         *
 * developers.  The maidsafe-dht_config.h file included is where configuration *
 * may be saved.  You MUST link the maidsafe-dht library.                      *
 *                                                                             *
 * NOTE: These APIs may be amended or deleted in future releases until this    *
 * notice is removed.                                                          *
 ******************************************************************************/

#ifndef MAIDSAFE_MAIDSAFE_DHT_H_
#define MAIDSAFE_MAIDSAFE_DHT_H_

#include <string>
#include <vector>
#include "maidsafe/maidsafe-dht_config.h"

#if MAIDSAFE_DHT_VERSION < 10
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

// Kademlia
namespace kad {

class SignedValue;

class KNode {
 public:
  KNode(boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
      node_type type, const std::string &private_key,
      const std::string &public_key, const bool &port_forwarded,
      const bool &use_upnp);
  // constructor used to set up parameters K, alpha, and beta for kademlia
  KNode(boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
      node_type type, const boost::uint16_t k, const int &alpha,
      const int &beta, const int &refresh_time, const std::string &private_key,
      const std::string &public_key, const bool &port_forwarded,
      const bool &use_upnp);
  ~KNode();
  // Join the network with a specific node ID.
  void Join(const std::string &node_id, const std::string &kad_config_file,
      base::callback_func_type cb);
  // Join the network with a random node ID.
  void Join(const std::string &kad_config_file, base::callback_func_type cb);
  // Start a network (this being the first node) with a specific node ID.
  void Join(const std::string &node_id, const std::string &kad_config_file,
      const std::string &external_ip, const boost::uint16_t &external_port,
      base::callback_func_type cb);
  // Start a network (this being the first node) with a random node ID.
  void Join(const std::string &kad_config_file, const std::string &external_ip,
      const boost::uint16_t &external_port, base::callback_func_type cb);
  void Leave();
  void StoreValue(const std::string &key, const SignedValue &value,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &signed_request, const boost::uint32_t &ttl,
      base::callback_func_type cb);
  void StoreValue(const std::string &key, const std::string &value,
      const boost::uint32_t &ttl, base::callback_func_type cb);
  // If any KNode during the iterative lookup has the value in its
  // AlternativeStore, rather than returning this value, it returns its own
  // contact details.  If check_alt_store is true, this node checks its own
  // AlternativeStore also.
  void FindValue(const std::string &key, const bool &check_alt_store,
      base::callback_func_type cb);
  void FindNode(const std::string &node_id, base::callback_func_type cb,
      const bool &local);
  void FindCloseNodes(const std::string &node_id, base::callback_func_type cb);
  void FindKClosestNodes(const std::string &key,
      std::vector<Contact> *close_nodes,
      const std::vector<Contact> &exclude_contacts);
  void Ping(const std::string &node_id, base::callback_func_type cb);
  void Ping(const Contact &remote, base::callback_func_type cb);
  int AddContact(Contact new_contact, const float & rtt,
      const bool &only_db);
  void RemoveContact(const std::string &node_id);
  bool GetContact(const std::string &id, Contact *contact);
  bool FindValueLocal(const std::string &key, std::vector<std::string> *values);
  bool StoreValueLocal(const std::string &key, const std::string &value,
      const boost::uint32_t &ttl);
  bool RefreshValueLocal(const std::string &key, const std::string &value,
      const boost::uint32_t &ttl);
  void GetRandomContacts(const int &count,
      const std::vector<Contact> &exclude_contacts,
      std::vector<Contact> *contacts);
  void HandleDeadRendezvousServer(const bool &dead_server);
  connect_to_node CheckContactLocalAddress(const std::string &id,
      const std::string &ip, const uint16_t &port, const std::string &ext_ip);
  void UpdatePDRTContactToRemote(const std::string &node_id);
  ContactInfo contact_info() const;
  void StopRvPing();
  std::string node_id() const;
  std::string host_ip() const;
  boost::uint16_t host_port() const;
  std::string local_host_ip() const;
  boost::uint16_t local_host_port() const;
  std::string rv_ip() const;
  boost::uint16_t rv_port() const;
  bool is_joined() const;
  KadRpcs* kadrpcs();
  boost::uint32_t KeyLastRefreshTime(const std::string &key,
      const std::string &value);
  boost::uint32_t KeyExpireTime(const std::string &key,
      const std::string &value);
  bool HasRSAKeys();
  boost::uint32_t KeyValueTTL(const std::string &key,
      const std::string &value) const;
  // If this is set to a non-NULL value, then the AlternativeStore will be used
  // before Kad's native DataStore.
  void SetAlternativeStore(base::AlternativeStore* alternative_store);
  base::AlternativeStore *alternative_store();
 private:
  boost::shared_ptr<KNodeImpl> pimpl_;
};
}  // namespace kad


// RPC
namespace rpcprotocol {

class RpcMessage;

// Ensure that a one-to-one relationship is maintained between channelmanager &
// knode.
class ChannelManager {
 public:
  ChannelManager();
  ~ChannelManager();
  void RegisterChannel(const std::string &service_name, Channel* channel);
  void UnRegisterChannel(const std::string &service_name);
  void ClearChannels();
  void ClearCallLaters();
  int StartTransport(boost::uint16_t port,
      boost::function<void(const bool&, const std::string&,
                           const boost::uint16_t&)> notify_dead_server);
  int StartLocalTransport(const boost::uint16_t &port);
  int StopTransport();
  void CleanUpTransport();
  void MessageArrive(const RpcMessage &msg,
      const boost::uint32_t &connection_id, const float &rtt);
  boost::uint32_t CreateNewId();
  void AddPendingRequest(const boost::uint32_t &req_id, PendingReq req);
  bool DeletePendingRequest(const boost::uint32_t &req_id);
  void AddReqToTimer(const boost::uint32_t &req_id, const int &timeout);
  boost::shared_ptr<transport::Transport> ptransport();
  boost::uint16_t external_port() const;
  std::string external_ip() const;
  bool CheckConnection(const std::string &ip, const uint16_t &port);
  bool CheckLocalAddress(const std::string &local_ip,
      const std::string &remote_ip, const uint16_t &remote_port);
  void AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &req_id, const int &timeout);
  void AddChannelId(boost::uint32_t *id);
  void RemoveChannelId(const boost::uint32_t &id);
 private:
  boost::shared_ptr<ChannelManagerImpl> pimpl_;
};

class Controller : public google::protobuf::RpcController {
 public:
  Controller();
  ~Controller();
  void SetFailed(const std::string &failure);
  void Reset();
  bool Failed() const;
  std::string ErrorText() const;
  void StartCancel();
  bool IsCanceled() const;
  void NotifyOnCancel(google::protobuf::Closure*);
  void set_timeout(const int &seconds);
  void set_rtt(const float &rtt);
  void set_req_id(const boost::uint32_t &id);
  int timeout() const;
  float rtt() const;
  boost::uint32_t req_id() const;
 private:
  boost::shared_ptr<ControllerImpl> controller_pimpl_;
};

class Channel : public google::protobuf::RpcChannel {
 public:
  explicit Channel(rpcprotocol::ChannelManager *channelmanager);
  Channel(rpcprotocol::ChannelManager *channelmanager, const std::string &ip,
      const boost::uint16_t &port, const std::string &rv_ip,
      const boost::uint16_t &rv_port);
  ~Channel();
  void CallMethod(const google::protobuf::MethodDescriptor *method,
      google::protobuf::RpcController *controller,
      const google::protobuf::Message *request,
      google::protobuf::Message *response, google::protobuf::Closure *done);
  void SetService(google::protobuf::Service* service);
  void HandleRequest(const RpcMessage &request,
      const boost::uint32_t &connection_id, const float &rtt);
 private:
  boost::shared_ptr<ChannelImpl> pimpl_;
};
}  // namespace rpcprotocol

namespace transport {
class Transport {
 public:
  Transport();
  int ConnectToSend(const std::string &remote_ip, const uint16_t &remote_port,
      const std::string &rendezvous_ip, const uint16_t &rendezvous_port,
      boost::uint32_t *conn_id, const bool &keep_connection);
  int Send(const rpcprotocol::RpcMessage &data, const boost::uint32_t &conn_id,
      const bool &new_skt);
  int Start(uint16_t port, boost::function<void(const rpcprotocol::RpcMessage&,
        const boost::uint32_t&, const float &)> on_message,
      boost::function<void(const bool&, const std::string&,
        const boost::uint16_t&)> notify_dead_server,
      boost::function<void(const boost::uint32_t&, const bool&)> on_send);
  int StartLocal(const uint16_t &port, boost::function <void(
        const rpcprotocol::RpcMessage&, const boost::uint32_t&, const float &)>
        on_message,
      boost::function<void(const boost::uint32_t&, const bool&)> on_send);
  void CloseConnection(const boost::uint32_t &connection_id);
  void Stop();
  bool is_stopped() const;
  struct sockaddr& peer_address();
  bool GetPeerAddr(const boost::uint32_t &conn_id, struct sockaddr *addr);
  bool ConnectionExists(const boost::uint32_t &connection_id);
  bool HasReceivedData(const boost::uint32_t &connection_id, int64_t *size);
  boost::uint16_t listening_port();
  void StartPingRendezvous(const bool &directly_connected,
      const std::string &my_rendezvous_ip, const boost::uint16_t
      &my_rendezvous_port);
  void StopPingRendezvous();
  bool CanConnect(const std::string &ip, const uint16_t &port);
  bool CheckConnection(const std::string &local_ip,
      const std::string &remote_ip, const uint16_t &remote_port);
  void CleanUp();
  bool IsPortAvailable(const boost::uint16_t &port);
 private:
  boost::shared_ptr<TransportImpl> pimpl_;
};
}  // namespace transport

// callbacks section
// link our callback funtions to lower level
bool LostNet();
bool ChangedIP();

#endif  // MAIDSAFE_MAIDSAFE_DHT_H_
