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

#include "maidsafe/config.h"
#include "protobuf/transport_message.pb.h"
#include "transport/tcptransport.h"

namespace transport {

void fake_call() {
  printf("at fake call called by io service\n");
}

TCPTransport::TCPTransport()
    : id_(-1), listening_port_(0), outgoing_port_(0), current_id_(0),
      io_service_(), acceptor_(io_service_), stop_(true), rpcmsg_notifier_(),
      msg_notifier_(), service_routine_(), connections_(), conn_mutex_(),
      msg_handler_mutex_(), rpcmsg_handler_mutex_(), send_handler_mutex_(),
      peer_addr_() {
}

TCPTransport::~TCPTransport() {
  if (!stop_)
    Stop();
}

int TCPTransport::Start(const boost::uint16_t &port) {
  if (!stop_)
    return 1;
  if ((rpcmsg_notifier_.empty() && msg_notifier_.empty()) ||
       send_notifier_.empty())
    return 1;
  listening_port_ = port;
  boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(),
    listening_port_);
  acceptor_.open(endpoint.protocol());
  acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  boost::system::error_code ec;
  acceptor_.bind(endpoint, ec);
  if (ec) {
    acceptor_.close();
    DLOG(ERROR) << "Error starting tcp transport: " << ec << " - " <<
      ec.message() << "\n";
    return 1;
  }
  acceptor_.listen(boost::asio::socket_base::max_connections, ec);
  if (ec) {
    acceptor_.close();
    DLOG(ERROR) << "Error starting tcp transport: " << ec << " - " <<
      ec.message() << "\n";
    return 1;
  }

  tcpconnection_ptr new_connection(new TCPConnection(io_service_,
    boost::bind(&TCPTransport::HandleConnSend, this, _1, _2, _3, _4),
    boost::bind(&TCPTransport::HandleConnRecv, this, _1, _2, _3)));

  acceptor_.async_accept(new_connection->Socket(), peer_addr_,
    boost::bind(&TCPTransport::HandleAccept, this, new_connection,
      boost::asio::placeholders::error));
  stop_ = false;
  try {
    service_routine_.reset(new boost::thread(
      boost::bind(&TCPTransport::StartService, this)));
  } catch(const std::exception&) {
    stop_ = true;
    acceptor_.close();
//    delete new_connection;
    return 1;
  }
  current_id_ = base::generate_next_transaction_id(current_id_);
  if (port == 0)
    listening_port_ = acceptor_.local_endpoint().port();
  return 0;
}

int TCPTransport::StartLocal(const boost::uint16_t &port) {
  if (!stop_)
    return 1;
  if ((rpcmsg_notifier_.empty() && msg_notifier_.empty()) ||
       send_notifier_.empty())
    return 1;
  listening_port_ = port;
  boost::asio::ip::tcp::endpoint endpoint(
    boost::asio::ip::address_v4::loopback(),
    listening_port_);
  acceptor_.open(endpoint.protocol());
  acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  boost::asio::socket_base::keep_alive option(true);
  acceptor_.set_option(option);
  boost::system::error_code ec;
  acceptor_.bind(endpoint, ec);
  if (ec) {
    acceptor_.close();
    DLOG(ERROR) << "Error starting tcp transport: " << ec << " - " <<
      ec.message() << "\n";
    return 1;
  }
  acceptor_.listen(boost::asio::socket_base::max_connections, ec);
  if (ec) {
    acceptor_.close();
    DLOG(ERROR) << "Error starting tcp transport: " << ec << " - " <<
      ec.message() << "\n";
    return 1;
  }

  tcpconnection_ptr new_connection(new TCPConnection(io_service_,
    boost::bind(&TCPTransport::HandleConnSend, this, _1, _2, _3, _4),
    boost::bind(&TCPTransport::HandleConnRecv, this, _1, _2, _3)));

  acceptor_.async_accept(new_connection->Socket(),
    boost::bind(&TCPTransport::HandleAccept, this, new_connection,
      boost::asio::placeholders::error));
  stop_ = false;
  try {
    service_routine_.reset(new boost::thread(
      boost::bind(&TCPTransport::StartService, this)));
  } catch(const std::exception &e) {
    stop_ = true;
    acceptor_.close();
//    delete new_connection;
    return 1;
  }
  current_id_ = base::generate_next_transaction_id(current_id_);
  if (port == 0)
    listening_port_ = acceptor_.local_endpoint().port();
  return 0;
}

void TCPTransport::Stop() {
  if (stop_)
    return;
  io_service_.post(boost::bind(&TCPTransport::HandleStop, this));
  while (!stop_)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}

void TCPTransport::HandleStop() {
  boost::mutex::scoped_lock guard(conn_mutex_);
  std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
  for (it = connections_.begin(); it != connections_.end(); ++it) {
    it->second->Close();
//    delete it->second;
  }
  acceptor_.close();
  connections_.clear();
  stop_ = true;
}

void TCPTransport::CloseConnection(const boost::uint32_t &conn_id) {
  std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
  boost::mutex::scoped_lock guard(conn_mutex_);
  it = connections_.find(conn_id);
  if (it != connections_.end()) {
    it->second->Close();
//    delete it->second;
    connections_.erase(conn_id);
  }
}

bool TCPTransport::RegisterOnMessage(boost::function<void(const std::string&,
      const boost::uint32_t&, const boost::int16_t&,
      const float &)> on_message) {
  if (stop_) {
    msg_notifier_ = on_message;
    return true;
  }
  return false;
}

bool TCPTransport::RegisterOnRPCMessage(boost::function < void(
      const rpcprotocol::RpcMessage&, const boost::uint32_t&,
      const boost::int16_t&, const float &) > on_rpcmessage) {
  if (stop_) {
    rpcmsg_notifier_ = on_rpcmessage;
    return true;
  }
  return false;
}

bool TCPTransport::RegisterOnSend(boost::function < void(const boost::uint32_t&,
      const bool&) > on_send) {
  if (stop_) {
    send_notifier_ = on_send;
    return true;
  }
  return false;
}

bool TCPTransport::CanConnect(const std::string &ip,
      const boost::uint16_t &port) {
  if (stop_)
    return false;
  TCPConnection conn(io_service_, 0, 0);
  boost::asio::ip::tcp::endpoint addr;
  std::string dec_lip;
  if (ip.size() == 4)
    dec_lip = base::inet_btoa(ip);
  else
    dec_lip = ip;
  addr.address(boost::asio::ip::address::from_string(dec_lip));
  addr.port(port);
  bool result;
  if (outgoing_port_ == 0) {
    result = conn.Connect(addr);
    outgoing_port_ = conn.out_port();
  } else {
    result = conn.Connect(addr, outgoing_port_);
  }
  conn.Close();
  return result;
}

bool TCPTransport::ConnectionExists(const boost::uint32_t &connection_id) {
  std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
  boost::mutex::scoped_lock guard(conn_mutex_);
  it = connections_.find(connection_id);
  if (it != connections_.end())
    return true;
  return false;
}

bool TCPTransport::IsPortAvailable(const boost::uint16_t &port) {
  tcp::acceptor acceptor(io_service_);
  boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(),
    port);
  acceptor.open(endpoint.protocol());
  acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  boost::system::error_code ec;
  acceptor.bind(endpoint, ec);
  if (ec)
    return false;
  acceptor.listen(boost::asio::socket_base::max_connections, ec);
  if (ec)
    return false;
  acceptor.close();
  return true;
}

void TCPTransport::HandleAccept(tcpconnection_ptr conn,
    const boost::system::error_code &ec) {
  if (ec) {
    DLOG(ERROR) << "TCP(" << listening_port_ <<
      ") Error accepting a connection: " << ec << " - " << ec.message() << "\n";
    if (ec == boost::asio::error::operation_aborted)
      return;
    Stop();
    return;
  }
  {
    boost::mutex::scoped_lock guard(conn_mutex_);
    connections_[current_id_] = conn;
    conn->set_conn_id(current_id_);
    current_id_ = base::generate_next_transaction_id(current_id_);
  }
  conn->StartReceiving();
  tcpconnection_ptr new_connection(new TCPConnection(io_service_,
    boost::bind(&TCPTransport::HandleConnSend, this, _1, _2, _3, _4),
    boost::bind(&TCPTransport::HandleConnRecv, this, _1, _2, _3)));

  acceptor_.async_accept(new_connection->Socket(), peer_addr_,
    boost::bind(&TCPTransport::HandleAccept, this, new_connection,
      boost::asio::placeholders::error));
}

void TCPTransport::HandleConnSend(const boost::uint32_t &conn_id,
    const bool &send_once, const bool &rpc_sent,
    const boost::system::error_code &ec) {
  bool result(true);
  if (ec || send_once) {
    {
      boost::mutex::scoped_lock guard(conn_mutex_);
      std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
      it = connections_.find(conn_id);
      if (it != connections_.end()) {
        it->second->Close();
//        delete it->second;
        connections_.erase(it);
      }
    }
    if (ec) {
      DLOG(ERROR) << "TCP(" << listening_port_ <<
        ") Error writing to a socket: " << ec << " - " << ec.message() << "\n";
      result = false;
    }
  }
  if (rpc_sent) {
    boost::mutex::scoped_lock guard(send_handler_mutex_);
    send_notifier_(conn_id, result);
  }
  {
    boost::mutex::scoped_lock guard(conn_mutex_);
    std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
    it = connections_.find(conn_id);
    if (it != connections_.end()) {
      it->second->StartReceiving();
    }
  }
}

void TCPTransport::HandleConnRecv(const std::string &msg,
    const boost::uint32_t &conn_id, const boost::system::error_code &ec) {
  if (ec) {
    {
      boost::mutex::scoped_lock guard(conn_mutex_);
      std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
      it = connections_.find(conn_id);
      if (it != connections_.end()) {
        it->second->Close();
//        delete it->second;
        connections_.erase(it);
      }
    }
    DLOG(ERROR) << "TCP(" << listening_port_ <<
      ") Error reading from a socket: " << ec << " - " << ec.message() << "\n";
    return;
  }

  TransportMessage t_msg;
  if (t_msg.ParseFromString(msg)) {
    if (t_msg.has_rpc_msg() && !rpcmsg_notifier_.empty()) {
      boost::mutex::scoped_lock guard(rpcmsg_handler_mutex_);
      rpcmsg_notifier_(t_msg.rpc_msg(), conn_id, id_, 0.0);
    }
  } else if (!msg_notifier_.empty()) {
    boost::mutex::scoped_lock guard(msg_handler_mutex_);
    msg_notifier_(msg, conn_id, id_, 0.0);
  } else {
    LOG(WARNING) << "TCP(" << listening_port_ <<
        ") Invalid Message received" << std::endl;
  }

  // Starting the async read operation of the connection
  {
    boost::mutex::scoped_lock guard(conn_mutex_);
    std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
    it = connections_.find(conn_id);
    if (it != connections_.end()) {
      it->second->StartReceiving();
    }
  }
}

bool TCPTransport::GetPeerAddr(const boost::uint32_t &conn_id,
    struct sockaddr *addr) {
  std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
  boost::mutex::scoped_lock guard(conn_mutex_);
  it = connections_.find(conn_id);
  if (it != connections_.end()) {
    boost::system::error_code error;
    addr = reinterpret_cast<sockaddr*>(
      it->second->RemoteEndPoint(error).data());
    if (error)
      return false;
    else
      return true;
  }
  return false;
}

bool TCPTransport::HasReceivedData(const boost::uint32_t &connection_id,
    boost::int64_t *size) {
  std::map<boost::uint32_t, tcpconnection_ptr>::iterator it;
  boost::mutex::scoped_lock guard(conn_mutex_);
  it = connections_.find(connection_id);
  if (it != connections_.end()) {
    if (it->second->in_data().size() > *size ||
       it->second->in_data_size() == *size) {
      *size = it->second->in_data().size();
      return true;
    }
  }
  return false;
}

int TCPTransport::ConnectToSend(const std::string &remote_ip, const uint16_t
      &remote_port, const std::string&, const uint16_t&, const std::string&,
      const uint16_t&, const bool &keep_connection, boost::uint32_t *conn_id) {
  tcpconnection_ptr conn(new TCPConnection(io_service_,
    boost::bind(&TCPTransport::HandleConnSend, this, _1, _2, _3, _4),
    boost::bind(&TCPTransport::HandleConnRecv, this, _1, _2, _3)));
  boost::asio::ip::tcp::endpoint addr;
  std::string dec_lip;
  if (remote_ip.size() == 4)
    dec_lip = base::inet_btoa(remote_ip);
  else
    dec_lip = remote_ip;
  addr.address(boost::asio::ip::address::from_string(dec_lip));
  addr.port(remote_port);
  bool result;
  if (outgoing_port_ == 0) {
    result = conn->Connect(addr);
    outgoing_port_ = conn->out_port();
  } else {
    result = conn->Connect(addr, outgoing_port_);
  }
  if (!result)
    return 1;
  {
    boost::mutex::scoped_lock guard(conn_mutex_);
    connections_[current_id_] = conn;
    conn->set_conn_id(current_id_);
    *conn_id = current_id_;
    current_id_ = base::generate_next_transaction_id(current_id_);
  }
  if (keep_connection)
    conn->send_once(false);
  return 0;
}

int TCPTransport::Send(const rpcprotocol::RpcMessage &data,
      const boost::uint32_t &conn_id, const bool&) {
  if (data.IsInitialized()) {
    TransportMessage t_msg;
    rpcprotocol::RpcMessage *rpc_msg = t_msg.mutable_rpc_msg();
    *rpc_msg = data;
    std::string ser_tmsg(t_msg.SerializeAsString());
    {
      boost::mutex::scoped_lock guard(conn_mutex_);
      std::map<boost::uint32_t, tcpconnection_ptr>::iterator it =
          connections_.find(conn_id);
      if (it != connections_.end()) {
        it->second->sending_rpc(true);
        it->second->Send(ser_tmsg);
      } else {
        return 1;
      }
    }
    return 0;
  } else {
    {
      boost::mutex::scoped_lock guard(conn_mutex_);
      std::map<boost::uint32_t, tcpconnection_ptr>::iterator it =
          connections_.find(conn_id);
      if (it != connections_.end()) {
        it->second->Close();
//        delete it->second;
        connections_.erase(it);
      }
    }
    return 1;
  }
}

int TCPTransport::Send(const std::string &data, const boost::uint32_t &conn_id,
      const bool&) {
  if (!data.empty()) {
    {
      boost::mutex::scoped_lock guard(conn_mutex_);
      std::map<boost::uint32_t, tcpconnection_ptr>::iterator it =
          connections_.find(conn_id);
      if (it != connections_.end()) {
        it->second->Send(data);
      } else {
        return 1;
      }
    }
    return 0;
  } else {
    {
      boost::mutex::scoped_lock guard(conn_mutex_);
      std::map<boost::uint32_t, tcpconnection_ptr>::iterator it =
          connections_.find(conn_id);
      if (it != connections_.end()) {
        it->second->Close();
//        delete it->second;
        connections_.erase(it);
      }
    }
    return 1;
  }
}

struct sockaddr& TCPTransport::peer_address() {
  struct sockaddr *addr = reinterpret_cast<sockaddr*>(peer_addr_.data());
  return *addr;
}

void TCPTransport::HandleStopIOService() {
  io_service_.reset();
}

void TCPTransport::StartService() {
  boost::this_thread::at_thread_exit(boost::bind(
    &TCPTransport::HandleStopIOService, this));
  io_service_.run();
}
}
