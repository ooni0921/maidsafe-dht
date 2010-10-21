/* Copyright (c) 2010 maidsafe.net limited
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

#include "maidsafe/transport/transportdb.h"

#include <boost/lexical_cast.hpp>

#include <list>
#include <string>
#include <utility>

#include "maidsafe/base/crypto.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/protobuf/transport_message.pb.h"

namespace transport {

/***************************** TransportDbHandler *****************************/

TransportDbHandler::TransportDbHandler(const std::string &table)
    : connection_(false), table_(table) {}

int TransportDbHandler::CreateDb(const std::string &database,
                                 const std::string &ip,
                                 const boost::uint16_t &port) {
  try {
    if (!connection_.connect(NULL, "127.0.0.1", "root", "m41ds4f3"))
      return -1;
    if (!connection_.select_db(database))
      if (!connection_.create_db(database) || !connection_.select_db(database))
        return -1;

    mysqlpp::Query query = connection_.query();
    query.exec("drop table " + table_);
    query.exec("drop table details");
    query.exec("create table " + table_ + "(message LONGBLOB NOT NULL,"
                                           "timestamp BIGINT NOT NULL,"
                                           "sender_db VARCHAR(32) NULL)");
    query.exec("create table details(ip VARCHAR(25) NOT NULL,"
                                    "port INT NOT NULL)");
    query << "INSERT INTO details VALUES('" << ip << "', " << port << ")";
    mysqlpp::SimpleResult res = query.execute();
    if (res.rows() != 1)
      return -1;
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

int TransportDbHandler::GetMessages(std::list<db_mock::FetchedMessage> *msgs) {
  try {
    boost::uint64_t now(base::GetEpochNanoseconds());
    mysqlpp::Query query = connection_.query();
    query << "LOCK TABLES " << table_ << " WRITE";
    mysqlpp::SimpleResult lock_res = query.execute();

    query = connection_.query();
    query << "SELECT message,sender_db FROM " << table_ << " where timestamp<"
          << now;

    mysqlpp::StoreQueryResult select_res = query.store();
    if (!select_res) {
      printf("Failed getting values\n");
      return -1;
    }

    query = connection_.query();
    query << "DELETE FROM " << table_ << " where timestamp<" << now;
    mysqlpp::SimpleResult delete_res = query.execute();
    for (size_t i = 0; i < select_res.num_rows(); ++i) {
      std::string s1, s2;
      select_res[i][0].to_string(s1);
      select_res[i][1].to_string(s2);
      db_mock::FetchedMessage fm(s1, s2);
      msgs->push_back(fm);
    }

    query = connection_.query();
    query << "UNLOCK TABLES";
    lock_res = query.execute();
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

int TransportDbHandler::InsertMessage(const std::string &peer_database,
                                      const std::string &message,
                                      const std::string &database) {
  try {
    mysqlpp::Connection c;
    if (!c.connect(peer_database.c_str(), "127.0.0.1", "root", "m41ds4f3"))
      return -1;
    mysqlpp::Query query = c.query();
    boost::uint64_t now(base::GetEpochNanoseconds());
    query << "INSERT INTO " << table_ << " VALUES('" << mysqlpp::escape
          << message << "', " << now << ", '" << database << "')";
    mysqlpp::SimpleResult res = query.execute();
    if (res.rows() != 1)
      return -1;
    c.disconnect();
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

int TransportDbHandler::ShutDown(const std::string &database) {
  try {
    mysqlpp::Query query = connection_.query();
//    query.exec("drop table " + table_);
    query.exec("drop database " + database);
    connection_.disconnect();
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

int TransportDbHandler::CheckPeerDb(const std::string &database) {
  try {
    mysqlpp::Connection c;
    if (!c.connect(database.c_str(), "127.0.0.1", "root", "m41ds4f3"))
      return -1;
    c.disconnect();
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

int TransportDbHandler::PeerEndpoint(const std::string &database,
                                     std::string *ip, boost::uint16_t *port) {
  try {
    mysqlpp::Connection c;
    if (!c.connect(database.c_str(), "127.0.0.1", "root", "m41ds4f3"))
      return -1;

    mysqlpp::Query query = c.query();
    query << "SELECT * FROM details";

    mysqlpp::StoreQueryResult select_res = query.store();
    if (!select_res) {
      printf("Failed getting endpoint\n");
      return -1;
    }
    select_res[0][0].to_string(*ip);
    std::string s_port;
    select_res[0][1].to_string(s_port);

    *port = boost::uint16_t(boost::lexical_cast<boost::uint16_t>(s_port));
    c.disconnect();
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

/********************************* TransportDb ********************************/

TransportDb::TransportDb() : db_handler_("incoming"), transport_id_(0), id_(0),
                             id_database_map_(), iddbmap_mutex_(),
                             rpc_message_notifier_(), message_notifier_(),
                             server_down_notifier_(), send_notifier_(),
                             stop_(true), listening_port_(0),
                             get_messages_routine_(),
                             clear_connections_routine_() {}

TransportDb::~TransportDb() {}

TransportType TransportDb::transport_type() { return kOther; }

boost::int16_t TransportDb::transport_id() { return transport_id_; }

void TransportDb::set_transport_id(const boost::int16_t &id) {
  transport_id_ = id;
}

bool TransportDb::is_stopped() const { return stop_; }

bool TransportDb::peer_address(struct sockaddr*) { return true; }

boost::uint16_t TransportDb::listening_port() { return listening_port_; }

int TransportDb::Start(const boost::uint16_t &port) {
  if (rpc_message_notifier_.empty() || server_down_notifier_.empty() ||
      send_notifier_.empty())
    return -1;

  stop_ = false;
  int n = SetupDb(port);
  if (n != 0)
    return n;

  SetupThreads();

  return 0;
}

int TransportDb::SetupDb(const boost::uint16_t &port) {
  boost::asio::ip::address local_address;
  base::GetLocalAddress(&local_address);
  std::string peer_db(local_address.to_string() +
                      boost::lexical_cast<std::string>(port));
  crypto::Crypto co;
  int n = db_handler_.CreateDb(co.Hash(peer_db, "", crypto::STRING_STRING,
                                       true).substr(0, 31),
                               local_address.to_string(), port);
  if (n != 0)
    return n;

  listening_port_ = port;

  return 0;
}

void TransportDb::SetupThreads() {
  get_messages_routine_ =
      boost::thread(boost::bind(&TransportDb::CheckForMessages, this));
  clear_connections_routine_ =
      boost::thread(boost::bind(&TransportDb::CheckForStaleConnections, this));
}

int TransportDb::StartLocal(const boost::uint16_t&) { return 0; }

void TransportDb::Stop() {
  if (stop_)
    return;
  stop_ = true;
  {
    boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
    id_database_map_.clear();
  }
  get_messages_routine_.join();
  clear_connections_routine_.join();

  boost::asio::ip::address local_address;
  base::GetLocalAddress(&local_address);
  crypto::Crypto co;
  std::string peer_db(co.Hash(local_address.to_string() +
                              boost::lexical_cast<std::string>(listening_port_),
                              "", crypto::STRING_STRING, true).substr(0, 31));
  /*int n = */db_handler_.ShutDown(peer_db);

//  rpc_message_notifier_.clear();
//  message_notifier_.clear();
//  server_down_notifier_.clear();
//  send_notifier_.clear();
}

int TransportDb::ConnectToSend(const std::string &remote_ip,
                               const boost::uint16_t &remote_port,
                               const std::string&, const boost::uint16_t&,
                               const std::string&, const boost::uint16_t&,
                               const bool &keep_alive,
                               boost::uint32_t *connection_id) {
  boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
  *connection_id = 0;
  crypto::Crypto co;
  std::string peer_db(co.Hash(remote_ip +
                              boost::lexical_cast<std::string>(remote_port), "",
                              crypto::STRING_STRING, true).substr(0, 31));

  if (db_handler_.CheckPeerDb(peer_db) != 0) {
    return -1;
  }

  db_mock::ConnectionStatus cs(peer_db, remote_ip, remote_port, keep_alive);
  *connection_id = ++id_;
  std::pair<IdDbMap::iterator, bool> p =
      id_database_map_.insert(IdDbPair(id_, cs));
  if (!p.second) {
    *connection_id = 0;
    return -1;
  }

  return 0;
}

int TransportDb::Send(const rpcprotocol::RpcMessage &data,
                      const boost::uint32_t &connection_id,
                      const bool &new_socket) {
  if (!data.IsInitialized())
    return -1;
  TransportMessage msg;
  rpcprotocol::RpcMessage *rpc_msg = msg.mutable_rpc_msg();
  *rpc_msg = data;
  std::string ser_message(msg.SerializeAsString());
  return Send(ser_message, connection_id, new_socket);
}

int TransportDb::Send(const std::string &data,
                      const boost::uint32_t &connection_id, const bool&) {
  if (data.empty())
    return -1;

  boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
  IdDbMap::iterator it = id_database_map_.find(connection_id);
  if (it == id_database_map_.end()) {
    return -1;
  }

  std::string my_db;
  crypto::Crypto co;
  if ((*it).second.keep_alive) {
    boost::asio::ip::address local_address;
    base::GetLocalAddress(&local_address);
    my_db = co.Hash(local_address.to_string() +
                    boost::lexical_cast<std::string>(listening_port_),
                    "", crypto::STRING_STRING, true).substr(0, 31);
  }

  int n = db_handler_.InsertMessage((*it).second.database, data, my_db);
  if (n != 0) {
    return n;
  }

  send_notifier_((*it).first, true);

  if (!(*it).second.keep_alive)
    id_database_map_.erase(it);

  return 0;
}

bool TransportDb::RegisterOnRPCMessage(RpcMsgNotifier on_rpcmessage) {
  rpc_message_notifier_ = on_rpcmessage;
  return true;
}

bool TransportDb::RegisterOnMessage(MsgNotifier on_message) {
  message_notifier_ = on_message;
  return true;
}

bool TransportDb::RegisterOnSend(SentNotifier on_send) {
  send_notifier_ = on_send;
  return true;
}

bool TransportDb::RegisterOnServerDown(ServerDownNotifier on_server_down) {
  server_down_notifier_ = on_server_down;
  return true;
}

void TransportDb::CloseConnection(const boost::uint32_t &connection_id) {
  boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
  IdDbMap::iterator it = id_database_map_.find(connection_id);
  if (it != id_database_map_.end())
    id_database_map_.erase(it);
}

bool TransportDb::GetPeerAddr(const boost::uint32_t &id, struct sockaddr *s) {
  boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
  IdDbMap::iterator it = id_database_map_.find(id);
  if (it == id_database_map_.end()) {
    return false;
  }

  std::string ip;
  boost::uint16_t port(0);
  if ((*it).second.ip.empty() || (*it).second.port == 0) {
    if (!(*it).second.database.empty()) {
      int n = db_handler_.PeerEndpoint((*it).second.database, &ip, &port);
      if (n != 0 || ip.empty() || port == 0) {
        return false;
      }
    }
  }

  if (ip.empty() || port == 0)
    return false;

  struct sockaddr_in ip4addr;
  ip4addr.sin_family = AF_INET;
  ip4addr.sin_port = htons(port);
  inet_aton(ip.c_str(), &ip4addr.sin_addr);
  *s = *((struct sockaddr*)&ip4addr);

  return true;
}

bool TransportDb::ConnectionExists(const boost::uint32_t &id) {
  boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
  IdDbMap::iterator it = id_database_map_.find(id);
  if (it == id_database_map_.end())
    return false;

  return true;
}

bool TransportDb::HasReceivedData(const boost::uint32_t&, boost::int64_t*) {
  return false;
}

void TransportDb::StartPingRendezvous(const bool&, const std::string&,
                                      const boost::uint16_t&) {}

void TransportDb::StopPingRendezvous() {}

bool TransportDb::CanConnect(const std::string &ip,
                             const boost::uint16_t &port) {
  std::string peer_db(ip + boost::lexical_cast<std::string>(port));
  crypto::Crypto co;
  int n = db_handler_.CheckPeerDb(co.Hash(peer_db, "", crypto::STRING_STRING,
                                          true).substr(0, 31));
  return n == 0 ? true : false;
}

bool TransportDb::IsAddressUsable(const std::string&, const std::string&,
                                  const boost::uint16_t&) {
  return true;
}

bool TransportDb::IsPortAvailable(const boost::uint16_t&) { return true; }

void TransportDb::CheckForMessages() {
  std::list<db_mock::FetchedMessage> messages;
  while (!stop_) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    db_handler_.GetMessages(&messages);
    while (!messages.empty()) {
      TransportMessage tmsg;
      if (tmsg.ParseFromString(messages.front().message)) {
        if (tmsg.has_rpc_msg() && !rpc_message_notifier_.empty()) {
          int msg_id(0);
          if (!messages.front().senders_db.empty()) {
            boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
            db_mock::ConnectionStatus cs(messages.front().senders_db, "", 0,
                                         false);
            std::pair<IdDbMap::iterator, bool> p =
                id_database_map_.insert(IdDbPair(++id_, cs));
            if (!p.second)
              return;
            msg_id = id_;
          }
          rpc_message_notifier_(tmsg.rpc_msg(), msg_id, transport_id(), 1);
        }
      } else if (!message_notifier_.empty()) {
        int msg_id(0);
        if (!messages.front().senders_db.empty()) {
          boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
          db_mock::ConnectionStatus cs(messages.front().senders_db, "", 0,
                                       false);
          std::pair<IdDbMap::iterator, bool> p =
              id_database_map_.insert(IdDbPair(++id_, cs));
          if (!p.second)
            return;
          msg_id = id_;
        }
        message_notifier_(messages.front().message, msg_id, transport_id(), 1);
      } else {
        LOG(WARNING) << "( " << listening_port_ << ") Invalid Message received"
                     << std::endl;
      }
      messages.pop_front();
    }
  }
}

void TransportDb::CheckForStaleConnections() {
  boost::uint8_t rounds;
  while (!stop_) {
    rounds = 1;
    while (rounds < boost::uint8_t(30)) {
      if (stop_) {
        rounds = 30;
      } else {
        boost::this_thread::sleep(boost::posix_time::seconds(2));
        ++rounds;
      }
    }

    boost::mutex::scoped_lock loch_errochty(iddbmap_mutex_);
    boost::uint32_t now(base::GetEpochTime());
    IdDbMap::iterator it = id_database_map_.begin();
    while (it != id_database_map_.end()) {
      if ((*it).second.timestamp + 50 < now) {
        id_database_map_.erase(it++);
      } else {
        ++it;
      }
    }
  }
}

}  // namespace transport
