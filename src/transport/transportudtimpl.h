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

#ifndef TRANSPORT_TRANSPORTUDTIMPL_H_
#define TRANSPORT_TRANSPORTUDTIMPL_H_

#include <boost/cstdint.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>
#include <boost/thread/mutex.hpp>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "maidsafe/maidsafe-dht_config.h"
#include "protobuf/transport_message.pb.h"
#include "maidsafe/transport-api.h"
#include "udt/udt.h"

namespace transport {

struct IncomingMessages {
  IncomingMessages(const boost::uint32_t &id,
                   const boost::int16_t &transid)
    : msg(), raw_data(""), conn_id(id), trans_id(transid), rtt(0) {}
  IncomingMessages() : msg(), raw_data(""), conn_id(), trans_id() {}
  rpcprotocol::RpcMessage msg;
  std::string raw_data;
  boost::uint32_t conn_id;
  boost::int16_t trans_id;
  double rtt;
};

struct IncomingData {
  UDTSOCKET u;
  int64_t expect_size;
  int64_t received_size;
  boost::shared_array<char> data;
  double accum_RTT;
  boost::uint32_t observations;
};

struct OutgoingData {
  UDTSOCKET u;
  int64_t data_size;
  int64_t data_sent;
  boost::shared_array<char> data;
  bool sent_size;
  boost::uint32_t conn_id;
  bool is_rpc;
};

class TransportUDTImpl {
 public:
  TransportUDTImpl();
  ~TransportUDTImpl();
  enum DataType { kString, kFile };
  Transport::TransportType GetType();
  boost::int16_t GetID() { return trans_id_; }
  void SetID(const boost::int16_t &id) { trans_id_ = id; }
  static void CleanUp();
  int ConnectToSend(const std::string &remote_ip,
                   const boost::uint16_t &remote_port,
                   const std::string &local_ip,
                   const boost::uint16_t &local_port,
                   const std::string &rendezvous_ip,
                   const boost::uint16_t &rendezvous_port,
                   const bool &keep_connection,
                   boost::uint32_t *conn_id);
  int Send(const rpcprotocol::RpcMessage &data,
           const boost::uint32_t &conn_id,
           const bool &new_skt);
  int Send(const std::string &data,
           const boost::uint32_t &conn_id,
           const bool &new_skt);
  int Start(const boost::uint16_t & port);
  int StartLocal(const boost::uint16_t &port);
  bool RegisterOnRPCMessage(
      boost::function<void(const rpcprotocol::RpcMessage&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float &)> on_rpcmessage);
  bool RegisterOnMessage(
      boost::function<void(const std::string&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float &)> on_message);
  bool RegisterOnSend(
      boost::function<void(const boost::uint32_t&,
                           const bool&)> on_send);
  bool RegisterOnServerDown(
      boost::function<void(const bool&,
                           const std::string&,
                           const boost::uint16_t&)> on_server_down);
  void CloseConnection(const boost::uint32_t &connection_id);
  void Stop();
  inline bool is_stopped() const { return stop_; }
  struct sockaddr& peer_address() { return peer_address_; }
  bool GetPeerAddr(const boost::uint32_t &conn_id, struct sockaddr *addr);
  bool ConnectionExists(const boost::uint32_t &connection_id);
  bool HasReceivedData(const boost::uint32_t &connection_id,
                       boost::int64_t *size);
  boost::uint16_t listening_port();
  void StartPingRendezvous(const bool &directly_connected,
                           const std::string &my_rendezvous_ip,
                           const boost::uint16_t &my_rendezvous_port);
  void StopPingRendezvous();
  bool CanConnect(const std::string &ip, const boost::uint16_t &port);
  bool IsAddrUsable(const std::string &local_ip,
                    const std::string &remote_ip,
                    const boost::uint16_t &remote_port);
  bool IsPortAvailable(const boost::uint16_t &port);
 private:
  TransportUDTImpl& operator=(const TransportUDTImpl&);
  TransportUDTImpl(TransportUDTImpl&);
  void AddIncomingConnection(UDTSOCKET u);
  void AddIncomingConnection(UDTSOCKET u, boost::uint32_t *conn_id);
  void HandleRendezvousMsgs(const HolePunchingMsg &message);
  int Send(const std::string &data, DataType type,
      const boost::uint32_t &conn_id, const bool &new_skt, const bool &is_rpc);
  void SendHandle();
  int Connect(UDTSOCKET *skt, const std::string &peer_address,
      const boost::uint16_t &peer_port);
  void PingHandle();
  void AcceptConnHandler();
  void ReceiveHandler();
  void MessageHandler();
  volatile bool stop_;
  boost::function<void(const rpcprotocol::RpcMessage&,
                       const boost::uint32_t&,
                       const boost::int16_t&,
                       const float&)> rpcmsg_notifier_;
  boost::function<void(const std::string&,
                       const boost::uint32_t&,
                       const boost::int16_t&,
                       const float&)> msg_notifier_;
  boost::function<void(const bool&, const std::string&,
                       const boost::uint16_t&)> server_down_notifier_;
  boost::shared_ptr<boost::thread> accept_routine_,
                                   recv_routine_,
                                   send_routine_,
                                   ping_rendz_routine_,
                                   handle_msgs_routine_;
  UDTSOCKET listening_socket_;
  struct sockaddr peer_address_;
  boost::uint16_t listening_port_, my_rendezvous_port_;
  std::string my_rendezvous_ip_;
  std::map<boost::uint32_t, IncomingData> incoming_sockets_;
  std::list<OutgoingData> outgoing_queue_;
  std::list<IncomingMessages> incoming_msgs_queue_;
  boost::mutex send_mutex_,
               ping_rendez_mutex_,
               recv_mutex_,
               msg_hdl_mutex_,
               s_skts_mutex_;
  struct addrinfo addrinfo_hints_;
  struct addrinfo* addrinfo_res_;
  boost::uint32_t current_id_;
  boost::condition_variable send_cond_,
                            ping_rend_cond_,
                            recv_cond_,
                            msg_hdl_cond_;
  bool ping_rendezvous_, directly_connected_/*, handle_non_transport_msgs_*/;
  int accepted_connections_, msgs_sent_;
  boost::uint32_t last_id_;
  std::set<boost::uint32_t> data_arrived_;
  std::map<boost::uint32_t, struct sockaddr> ips_from_connections_;
  boost::function<void(const boost::uint32_t&, const bool&)> send_notifier_;
  std::map<boost::uint32_t, UDTSOCKET> send_sockets_;
  Transport::TransportType transportType_;
  boost::int16_t trans_id_;
};

};  // namespace transport

#endif  // TRANSPORT_TRANSPORTUDTIMPL_H_
