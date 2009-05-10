/*
Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 *  Created on: Sep 29, 2008
 *      Author: haiyang
 */

#ifndef KADEMLIA_CONTACT_H_
#define KADEMLIA_CONTACT_H_

#include <boost/cstdint.hpp>
#include <string>

namespace kad {

class Contact {
// This class contains information on a single remote contact
 public:
  Contact(const std::string &node_id,
          const std::string &host_ip,
          const boost::uint16_t &host_port,
          const std::string &local_ip,
          const boost::uint16_t &local_port,
          const std::string &rendezvous_ip,
          const boost::uint16_t &rendezvous_port);
  Contact(const std::string &node_id,
          const std::string &host_ip,
          const boost::uint16_t &host_port);
  Contact(const std::string &node_id,
          const std::string &host_ip,
          const boost::uint16_t &host_port,
          const std::string &local_ip,
          const boost::uint16_t &local_port);
  Contact();
  // copy ctor
  Contact(const Contact&rhs);
  // Test whether this contact is equal to another according node id or (ip,
  // port)
  bool operator == (const Contact &other);
  bool operator != (const Contact &other);
  Contact& operator=(const Contact &other) {  // clone the content from another
    this->node_id_ = other.node_id_;
    this->host_ip_ = other.host_ip_;
    this->host_port_ = other.host_port_;
    this->failed_rpc_ = other.failed_rpc_;
    this->rendezvous_ip_ = other.rendezvous_ip();
    this->rendezvous_port_ = other.rendezvous_port();
    this->last_seen_ = other.last_seen();
    this->local_ip_ = other.local_ip_;
    this->local_port_ = other.local_port_;
    return *this;
  }
  bool SerialiseToString(std::string *ser_output);
  bool ParseFromString(const std::string &data);
  inline const std::string& node_id() const { return node_id_; }
  inline const std::string& host_ip() const { return host_ip_; }
  inline boost::uint16_t host_port() const { return host_port_; }
  inline boost::uint16_t failed_rpc() const { return failed_rpc_; }
  inline void IncreaseFailed_RPC() { ++failed_rpc_; }
  const std::string& rendezvous_ip() const { return rendezvous_ip_; }
  boost::uint16_t rendezvous_port() const { return rendezvous_port_; }
  std::string ToString();
  inline boost::uint64_t last_seen() const { return last_seen_; }
  inline void set_last_seen(boost::uint64_t last_seen) {
    last_seen_ = last_seen;
  }
  inline const std::string& local_ip() const { return local_ip_; }
  inline boost::uint16_t local_port() const { return local_port_; }
 private:
  std::string node_id_;
  std::string host_ip_;
  boost::uint16_t host_port_;
  boost::uint16_t failed_rpc_;
  std::string rendezvous_ip_;
  boost::uint16_t rendezvous_port_;
  boost::uint64_t last_seen_;
  std::string local_ip_;
  boost::uint16_t local_port_;
};
}  // namespace kad

#endif  // KADEMLIA_CONTACT_H_
