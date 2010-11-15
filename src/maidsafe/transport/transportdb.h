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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTDB_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTDB_H_

#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/base/utils.h>
#include <maidsafe/transport/transport-api.h>

#include <list>
#include <map>
#include <string>
#include <utility>


namespace mysqlpp {
class Connection;
}  // namespace mysqlpp

namespace net_client {
class MySqlppWrap;
}  // namespace net_client

namespace rpcprotocol {
class RpcMessage;
}  // namespace rpcprotocol

namespace transport {

namespace db_mock {

struct ConnectionStatus {
  ConnectionStatus(const std::string &db,  // const std::string &lip,
                   const boost::uint16_t lport, bool ka)
      : database(db), /* ip(lip), */ port(lport), keep_alive(ka),
        timestamp(base::GetEpochTime()) {}
  std::string database;  // , ip;
  boost::uint16_t port;
  bool keep_alive;
  boost::uint32_t timestamp;
};

struct FetchedMessage {
  FetchedMessage(const std::string &msg, const std::string &db)
      : message(msg), senders_db(db) {}
  std::string message, senders_db;
};

}  // namespace db_mock

class TransportDbHandler {
 public:
  explicit TransportDbHandler(const std::string &table);
  int CreateDb(const std::string &database, const std::string &ip,
               const boost::uint16_t &port);
  int GetMessages(std::list<db_mock::FetchedMessage> *msgs);
  int InsertMessage(const std::string &peer_database,
                    const std::string &message,
                    const std::string &database);
  int ShutDown(const std::string &database);
  int CheckPeerDb(const std::string &database);
  int PeerEndpoint(const std::string &database, std::string *ip,
                   boost::uint16_t *port);

 private:
  boost::shared_ptr<mysqlpp::Connection> connection_;
  std::string table_;
};

class TransportDb : public Transport {
  typedef std::map<boost::uint32_t, db_mock::ConnectionStatus> IdDbMap;
  typedef std::pair<boost::uint32_t, db_mock::ConnectionStatus> IdDbPair;
  typedef boost::function<void(const rpcprotocol::RpcMessage&,
                               const boost::uint32_t&, const boost::int16_t&,
                               const float&)>
          RpcMsgNotifier;
  typedef boost::function<void(const std::string&, const boost::uint32_t&,
                               const boost::int16_t&, const float&)>
          MsgNotifier;
  typedef boost::function<void(const bool&, const std::string&,
                               const boost::uint16_t&)>
          ServerDownNotifier;
  typedef boost::function<void(const boost::uint32_t&, const bool&)>
          SentNotifier;

 public:
  TransportDb();
  ~TransportDb();
  TransportType transport_type();
  boost::int16_t transport_id();
  void set_transport_id(const boost::int16_t &id);
  int ConnectToSend(const std::string &remote_ip,
                    const boost::uint16_t &remote_port,
                    const std::string &local_ip,
                    const boost::uint16_t &local_port,
                    const std::string &rendezvous_ip,
                    const boost::uint16_t &rendezvous_port,
                    const bool &keep_alive, boost::uint32_t *connection_id);
  int Send(const rpcprotocol::RpcMessage &data,
           const boost::uint32_t &connection_id, const bool &new_socket);
  int Send(const std::string &data, const boost::uint32_t &connection_id,
           const bool &new_socket);
  int Start(const boost::uint16_t &port);
  int StartLocal(const boost::uint16_t &port);
  bool RegisterOnRPCMessage(RpcMsgNotifier on_rpcmessage);
  bool RegisterOnMessage(MsgNotifier on_message);
  bool RegisterOnSend(SentNotifier on_send);
  bool RegisterOnServerDown(ServerDownNotifier on_server_down);
  void CloseConnection(const boost::uint32_t &connection_id);
  void Stop();
  bool is_stopped() const;
  bool peer_address(struct sockaddr *peer_addr);
  bool GetPeerAddr(const boost::uint32_t &id, struct sockaddr *s);
  bool ConnectionExists(const boost::uint32_t&);
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
  bool IsPortAvailable(const boost::uint16_t&);

 private:
  TransportDbHandler db_handler_;
  boost::int16_t transport_id_;
  boost::uint32_t id_;
  IdDbMap id_database_map_;
  boost::mutex iddbmap_mutex_;
  RpcMsgNotifier rpc_message_notifier_;
  MsgNotifier message_notifier_;
  ServerDownNotifier server_down_notifier_;
  SentNotifier send_notifier_;
  bool stop_;
  boost::uint16_t listening_port_;
  boost::thread get_messages_routine_;
  boost::thread clear_connections_routine_;

  std::string GetDbName(const boost::uint16_t &port);
  int SetupDb(const boost::uint16_t &port);
  void SetupThreads();
  void CheckForMessages();
  void CheckForStaleConnections();
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTDB_H_
