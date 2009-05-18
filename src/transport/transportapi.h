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

#ifndef TRANSPORT_TRANSPORTAPI_H_
#define TRANSPORT_TRANSPORTAPI_H_

#include <boost/cstdint.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>
#include <boost/thread/mutex.hpp>

#ifdef WIN32
  #include <ws2tcpip.h>
// dirvine - ugly ugly hack !!
#ifdef __MINGW__
void WSAAPI freeaddrinfo(struct addrinfo*);
int WSAAPI getaddrinfo(const char*, const char*, const struct addrinfo*,
  struct addrinfo**);
int WSAAPI getnameinfo(const struct sockaddr*, socklen_t, char*, DWORD,
  char*, DWORD, int);
#endif  // dirvines ugly ugly hack
#endif
#ifndef WIN32
  #include <netdb.h>
  #include <unistd.h>
  #include <cstdlib>
  #include <cstring>
#endif
#include <list>
#include <map>
#include <string>
#include <vector>
#include "udt/udt.h"
#include "protobuf/hole_puching_messages.pb.h"

namespace transport {

struct IncomingData {
  UDTSOCKET u;
  int64_t expect_size;
  int64_t received_size;
  boost::shared_array<char> data;
};

struct OutgoingData {
  UDTSOCKET u;
  int64_t data_size;
  int64_t data_sent;
  boost::shared_array<char> data;
  bool sent_size;
};

// a callback function notify the result of the operations
typedef boost::function<void(bool)> op_callback_func;  // NOLINT
class Transport {
 public:
  Transport();
  ~Transport() {}
//  Transport& operator=(const Transport&) { return *this; }
//  Transport(const Transport&)
//    :stop_(false),
//     on_line_(false),
//     message_notifier_(NULL),
//     listening_loop_(NULL),
//     listening_socket_() { UDT::startup(); }

  enum DataType { STRING, FILE };
  int Send(const std::string &remote_ip,
           uint16_t remote_port,
           const std::string &rendezvous_ip,
           uint16_t rendezvous_port,
           const std::string &data,
           DataType type,
           boost::uint32_t *conn_id,
           bool keep_connection);
  int Send(boost::uint32_t connection_id,
           const std::string &data,
           DataType type);
  int Start(uint16_t port,
            boost::function<void(const std::string&,
                                 const boost::uint32_t&)> on_message,
            boost::function<void(const bool&,
                                 const std::string&,
                                 const boost::uint16_t&)> notify_dead_server);
  void CloseConnection(boost::uint32_t connection_id);
  void Stop();  // stops the recieving loop
  // inline void set_on_line(bool on_line) { on_line_ = on_line; }
  // inline bool on_line() { return on_line_; }
  inline bool is_stopped() { return stop_; }
  struct sockaddr& peer_address() { return peer_address_; }
  void ReceiveMessage();
  bool HandleRendezvousMsgs(const std::string &message);
  bool ConnectionExists(boost::uint32_t connection_id);
  void AddIncomingConnection(UDTSOCKET u);
  void AddIncomingConnection(UDTSOCKET u, boost::uint32_t *conn_id);
  inline boost::shared_ptr<boost::mutex> mutex0() { return mutex_[0]; }
  inline boost::uint16_t listening_port() { return listening_port_; }
  void StartPingRendezvous(const bool &directly_connected,
                           std::string my_rendezvous_ip,
                           boost::uint16_t my_rendezvous_port);
  bool CanConnect(const std::string &ip, const uint16_t &port);
 private:
  Transport& operator=(const Transport&);
  Transport(const Transport&);
  void SendHandle();
  bool Connect(UDTSOCKET *skt, const std::string &peer_address,
      const uint16_t &peer_port, bool short_timeout);
  void PingHandle();
  volatile bool stop_;
  // bool on_line_;
  boost::function<void(const std::string&,
                  const boost::uint32_t&)> message_notifier_;
  boost::function<void(const bool&, const std::string&,
      const boost::uint16_t&)> rendezvous_notifier_;
  boost::shared_ptr<boost::thread> listening_loop_, recv_routine_,
      send_routine_, ping_rendezvous_loop_;
  UDTSOCKET listening_socket_;
  struct sockaddr peer_address_;
  boost::uint16_t listening_port_, my_rendezvous_port_;
  std::string my_rendezvous_ip_;
  std::map<boost::uint32_t, IncomingData> incoming_sockets_;
  std::list<OutgoingData> outgoing_queue_;
  std::vector< boost::shared_ptr<boost::mutex> > mutex_;
  struct addrinfo addrinfo_hints_;
  struct addrinfo* addrinfo_res_;
  boost::uint32_t current_id_;
  boost::condition_variable cond_;
  bool ping_rendezvous_;
  bool directly_connected_;
};

};  // namespace transport

#endif  // TRANSPORT_TRANSPORTAPI_H_
