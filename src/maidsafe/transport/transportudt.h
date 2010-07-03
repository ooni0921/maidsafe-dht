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
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/thread.hpp>
#include <maidsafe/transport/transport-api.h>
#include <list>
#include <map>
#include <set>
#include <string>


namespace rpcprotocol {
class RpcMessage;
}  // namespace rpcprotocol


namespace transport {


class HolePunchingMsg;
struct IncomingMessages;

typedef int UdtSocket;


struct IncomingData {
  explicit IncomingData(const UdtSocket &udt_socket)
      : udt_socket(udt_socket), expect_size(0), received_size(0), data(NULL),
        cumulative_rtt(0.0), observations(0) {}
  IncomingData()
      : udt_socket(), expect_size(0), received_size(0), data(NULL),
        cumulative_rtt(0.0), observations(0) {}
  UdtSocket udt_socket;
  boost::int64_t expect_size;
  boost::int64_t received_size;
  boost::shared_array<char> data;
  double cumulative_rtt;
  boost::uint32_t observations;
};

struct OutgoingData {
  OutgoingData()
      : udt_socket(), data_size(0), data_sent(0), data(NULL), sent_size(false)/*,
        connection_id(0), is_rpc(false)*/ {}
  OutgoingData(UdtSocket udt_socket, boost::int64_t data_size/*,
               boost::uint32_t connection_id, bool is_rpc*/)
      : udt_socket(udt_socket), data_size(data_size), data_sent(0),
        data(new char[data_size]), sent_size(false)/*,
        connection_id(connection_id), is_rpc(is_rpc)*/ {}
  UdtSocket udt_socket;
  boost::int64_t data_size;
  boost::int64_t data_sent;
  boost::shared_array<char> data;
  bool sent_size;
//   boost::uint32_t connection_id;
//   bool is_rpc;
};



class TransportUDT : public Transport {
 public:
  TransportUDT();
  ~TransportUDT();
  
  static void CleanUp();

  TransportCondition Send(const std::string &data,
                          const std::string &remote_ip,
                          const boost::uint16_t &remote_port);
  TransportCondition Send(const std::string &data,
                          const std::string &remote_ip,
                          const boost::uint16_t &remote_port,
                          const std::string &rendezvous_ip,
                          const boost::uint16_t &rendezvous_port);
  TransportCondition SendFile(const boost::filesystem::path &path,
                              const std::string &remote_ip,
                              const boost::uint16_t &remote_port);
  TransportCondition Send(const DataType &type,const std::string &data);
  TransportCondition StartListening(const boost::uint16_t & port,
                                    const std::string &ip);

  int StartLocal(const boost::uint16_t &port);
  void CloseConnection(const boost::uint32_t &connection_id);
  void StopListening();
  inline bool is_stopped() const { return stop_; }
  bool peer_address(struct sockaddr *peer_addr);
  bool GetPeerAddr(const boost::uint32_t &connection_id,
                   struct sockaddr *peer_address);
  bool ConnectionExists(const boost::uint32_t &connection_id);
  bool HasReceivedData(const boost::uint32_t &connection_id,
                       boost::int64_t *size);
  boost::uint16_t listening_port();
  void StartPingRendezvous(const bool &directly_connected,
                           const std::string &my_rendezvous_ip,
                           const boost::uint16_t &my_rendezvous_port);
  void StopPingRendezvous();
  bool CanConnect(const std::string &ip, const boost::uint16_t &port);
  bool IsAddressUsable(const std::string &local_ip,
                       const std::string &remote_ip,
                       const boost::uint16_t &remote_port);
  bool IsPortAvailable(const boost::uint16_t &port);
 private:
  TransportCondition ConnectToSend(const std::string &remote_ip,
                                   const boost::uint16_t &remote_port,
                                   const std::string &rendezvous_ip,
                                   const boost::uint16_t &rendezvous_port);
  TransportUDT& operator=(const TransportUDT&);
  TransportUDT(TransportUDT&);
  // needed for UDT to set up a connection to send to

  void AddIncomingConnection(UdtSocket udt_socket);
  void AddIncomingConnection(UdtSocket udt_socket,
                             boost::uint32_t *connection_id);
  void HandleRendezvousMsgs(const HolePunchingMsg &message);
  void SendHandle();
  int Connect(const std::string &peer_address, const boost::uint16_t &peer_port,
              UdtSocket *udt_socket);
  void PingHandle();
  void AcceptConnHandler();
  void ReceiveHandler();
  void MessageHandler();
  volatile bool stop_;

  boost::shared_ptr<boost::thread> accept_routine_,
                                   recv_routine_,
                                   send_routine_,
                                   ping_rendz_routine_,
                                   handle_msgs_routine_;
  UdtSocket listening_socket_;
  struct sockaddr peer_address_;
  boost::uint16_t listening_port_, my_rendezvous_port_;
  std::string my_rendezvous_ip_;
  std::map<boost::uint32_t, IncomingData> incoming_sockets_;
  std::list<OutgoingData> outgoing_queue_;
  std::list<IncomingMessages> incoming_msgs_queue_;
  boost::mutex send_mutex_, ping_rendez_mutex_, recv_mutex_, msg_hdl_mutex_;
  boost::mutex s_skts_mutex_;
  struct addrinfo addrinfo_hints_;
  struct addrinfo* addrinfo_res_;
  boost::uint32_t current_id_;
  boost::condition_variable send_cond_, ping_rend_cond_, recv_cond_;
  boost::condition_variable msg_hdl_cond_;
  bool ping_rendezvous_, directly_connected_/*, handle_non_transport_msgs_*/;
  int accepted_connections_, msgs_sent_;
  boost::uint32_t last_id_;
  std::set<boost::uint32_t> data_arrived_;
  std::map<boost::uint32_t, struct sockaddr> ips_from_connections_;
  std::map<boost::uint32_t, UdtSocket> send_sockets_;


};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_

