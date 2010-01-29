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

#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>
#include <exception>
#include <string>
#include "maidsafe/transporttcp.h"
#include "maidsafe/config.h"
#include "maidsafe/online.h"


namespace transport {
TransportTCP::TransportTCP() : io_service_(), stop_(true), rpcmsg_notifier_(),
    msg_notifier_(), server_down_notifier_(), accept_routine_(),
    recv_routine_(), send_routine_(), ping_rendz_routine_(),
    handle_msgs_routine_(), listening_socket_(io_service_),
    acceptor_(io_service_), peer_address_(), listening_port_(0),
    my_rendezvous_port_(0), my_rendezvous_ip_(""), incoming_sockets_(),
    outgoing_queue_(), incoming_msgs_queue_(), send_mutex_(),
    ping_rendez_mutex_(), recv_mutex_(), msg_hdl_mutex_(), s_skts_mutex_(),
    addrinfo_hints_(), addrinfo_res_(NULL), current_id_(0), send_cond_(),
    ping_rend_cond_(), recv_cond_(), msg_hdl_cond_(), ping_rendezvous_(false),
    directly_connected_(false), accepted_connections_(0), msgs_sent_(0),
    last_id_(0), data_arrived_(), ips_from_connections_(), send_notifier_(),
    send_sockets_(), transportType_(Transport::kTcp), trans_id_(0) {
  printf("Alec constructor\n");
  io_service_.run();
}

TransportTCP::~TransportTCP() {
  printf("Alec destructor\n");
  if (!stop_)
    Stop();
}

Transport::TransportType TransportTCP::GetType() {
  printf("Alec GetType\n");
  return transportType_;
}

boost::uint16_t TransportTCP::listening_port() {
  printf("Alec listening_port\n");
  return listening_port_;
}

int TransportTCP::Start(const boost::uint16_t &port) {
  printf("Alec Start\n");
  if (!stop_)  // If already started
    return 1;
  //  If callbacks aren't bound
  if ((rpcmsg_notifier_.empty() && msg_notifier_.empty()) ||
       server_down_notifier_.empty() || send_notifier_.empty())
    return 1;

  listening_port_ = port;
  acceptor_.async_accept(listening_socket_,
    boost::bind(&TransportTCP::handle_accept, this,
    boost::asio::placeholders::error));
}

void TransportTCP::handle_accept(const boost::system::error_code& error) {
  printf("Alec handle_accept\n");
  if (!error) {
      /* Do what we need to do when we accept */
      acceptor_.async_accept(listening_socket_,
        boost::bind(&TransportTCP::handle_accept, this,
        boost::asio::placeholders::error));
  }
}

int TransportTCP::Send(const std::string &data,
    DataType type, const boost::uint32_t &conn_id, const bool &new_skt,
    const bool &is_rpc) {
  printf("Alec Send\n");
  return 1;
}

void TransportTCP::Stop() {
  printf("Alec Stop\n");
}

void TransportTCP::ReceiveHandler() {
  printf("Alec ReceiveHandler\n");
}

void TransportTCP::AddIncomingConnection(boost::asio::ip::tcp::socket u,
      boost::uint32_t *conn_id) {
  printf("Alec AddIncomingConnection\n");
}

void TransportTCP::AddIncomingConnection(boost::asio::ip::tcp::socket u) {
  printf("Alec AddIncomingConnection\n");
}

void TransportTCP::CloseConnection(const boost::uint32_t &connection_id) {
  printf("Alec CloseConnection\n");
}

bool TransportTCP::ConnectionExists(const boost::uint32_t &connection_id) {
  printf("Alec ConnectionExists\n");
  return false;
}

bool TransportTCP::HasReceivedData(const boost::uint32_t &connection_id,
                                   boost::int64_t *size) {
  printf("Alec HasReceivedData\n");
  return false;
}

void TransportTCP::SendHandle() {
  printf("Alec SendHandle\n");
}

int TransportTCP::Connect(boost::asio::ip::tcp::socket *skt,
                          const std::string &peer_address,
                          const uint16_t &peer_port, bool short_timeout) {
  printf("Alec Connect\n");
  return 1;
}

void TransportTCP::HandleRendezvousMsgs(const HolePunchingMsg &message) {
  printf("Alec HandleRendezvousMsgs\n");
}

void TransportTCP::StartPingRendezvous(const bool &directly_connected,
      const std::string &my_rendezvous_ip, const boost::uint16_t
      &my_rendezvous_port) {
  printf("Alec StartPingRendezvous\n");
}

void TransportTCP::StopPingRendezvous() {
  printf("Alec StopPingRendezvous\n");
}

void TransportTCP::PingHandle() {
  printf("Alec PingHandle\n");
}

bool TransportTCP::CanConnect(const std::string &ip, const uint16_t &port) {
  printf("Alec CanConnect\n");
  return listening_socket_.is_open();
}

void TransportTCP::AcceptConnHandler() {
  printf("Alec AcceptConnHandler\n");
}

void TransportTCP::MessageHandler() {
  printf("Alec MessageHandler\n");
}

int TransportTCP::Send(const rpcprotocol::RpcMessage &data,
    const boost::uint32_t &conn_id, const bool &new_skt) {
  printf("Alec SendRPC\n");
  return 1;
}

int TransportTCP::Send(const std::string &data,
    const boost::uint32_t &conn_id, const bool &new_skt) {
  printf("Alec SendStr\n");
  return 1;
}

bool TransportTCP::IsAddrUsable(const std::string &local_ip,
      const std::string &remote_ip, const uint16_t &remote_port) {
  printf("Alec IsAddrUsable\n");
  return false;
}

bool TransportTCP::GetPeerAddr(const boost::uint32_t &conn_id,
    struct sockaddr *addr) {
  printf("Alec GetPeerAddr\n");
  return false;
}

int TransportTCP::ConnectToSend(const std::string &remote_ip,
                                const uint16_t &remote_port,
                                const std::string &local_ip,
                                const uint16_t &local_port,
                                const std::string &rendezvous_ip,
                                const uint16_t &rendezvous_port,
                                const bool &keep_connection,
                                boost::uint32_t *conn_id) {
  printf("Alec ConnectToSend\n");
  return 1;
}

int TransportTCP::StartLocal(const boost::uint16_t &port) {
  printf("Alec StartLocal\n");
  return 1;
}

bool TransportTCP::IsPortAvailable(const boost::uint16_t &port) {
  printf("Alec IsPortAvailable\n");
  return false;
}

bool TransportTCP::RegisterOnRPCMessage(
    boost::function<void(const rpcprotocol::RpcMessage&,
                         const boost::uint32_t&,
                         const boost::int16_t&,
                         const float &)> on_rpcmessage) {
  printf("Alec RegisterOnRPCMessage\n");
  if (stop_) {
    rpcmsg_notifier_ = on_rpcmessage;
    return true;
  }
  return false;
}

bool TransportTCP::RegisterOnMessage(
    boost::function<void(const std::string&,
                         const boost::uint32_t&,
                         const boost::int16_t&,
                         const float &)> on_message) {
  printf("Alec RegisterOnMessage\n");
  if (stop_) {
    msg_notifier_ = on_message;
    return true;
  }
  return false;
}

bool TransportTCP::RegisterOnSend(
    boost::function<void(const boost::uint32_t&,
                         const bool&)> on_send) {
  printf("Alec RegisterOnSend\n");
  if (stop_) {
    send_notifier_ = on_send;
    return true;
  }
  return false;
}

bool TransportTCP::RegisterOnServerDown(
    boost::function<void(const bool&,
                         const std::string&,
                         const boost::uint16_t&)> on_server_down) {
  printf("Alec RegisterOnServerDown\n");
  if (stop_) {
    server_down_notifier_ = on_server_down;
    return true;
  }
  return false;
}
};  // namespace transport
