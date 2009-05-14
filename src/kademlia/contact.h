/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
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
    this->rendezvous_ip_ = other.rendezvous_ip_;
    this->rendezvous_port_ = other.rendezvous_port_;
    this->last_seen_ = other.last_seen_;
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
