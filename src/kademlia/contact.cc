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
#include "base/utils.h"
#include "kademlia/contact.h"
#include "protobuf/contact_info.pb.h"

namespace kad {

Contact::Contact(const std::string &node_id,
                 const std::string &host_ip,
                 const boost::uint16_t &host_port,
                 const std::string &local_ip,
                 const boost::uint16_t &local_port,
                 const std::string &rendezvous_ip,
                 const boost::uint16_t &rendezvous_port)
    : node_id_(node_id),
      host_ip_(host_ip),
      host_port_(host_port),
      failed_rpc_(0),
      rendezvous_ip_(rendezvous_ip),
      rendezvous_port_(rendezvous_port),
      last_seen_(base::get_epoch_milliseconds()),
      local_ip_(local_ip),
      local_port_(local_port) {
  if (host_ip.size() > 4)
      host_ip_ = base::inet_atob(host_ip);
  else
    host_ip_ = host_ip;
  if (local_ip.size() > 4)
      local_ip_ = base::inet_atob(local_ip);
  else
    local_ip_ = local_ip;
  if (rendezvous_ip.size() > 4)
      rendezvous_ip_ = base::inet_atob(rendezvous_ip);
  else
    rendezvous_ip_ = rendezvous_ip;
}

Contact::Contact(const std::string &node_id,
                 const std::string &host_ip,
                 const boost::uint16_t &host_port)
    : node_id_(node_id),
      host_ip_(host_ip),
      host_port_(host_port),
      failed_rpc_(0),
      rendezvous_ip_(""),
      rendezvous_port_(0),
      last_seen_(base::get_epoch_milliseconds()),
      local_ip_(""),
      local_port_(0) {
  if (host_ip.size() > 4)
      host_ip_ = base::inet_atob(host_ip);
  else
    host_ip_ = host_ip;
}

Contact::Contact(const std::string &node_id,
                 const std::string &host_ip,
                 const boost::uint16_t &host_port,
                 const std::string &local_ip,
                 const boost::uint16_t &local_port)
    : node_id_(node_id),
      host_ip_(host_ip),
      host_port_(host_port),
      failed_rpc_(0),
      rendezvous_ip_(""),
      rendezvous_port_(0),
      last_seen_(base::get_epoch_milliseconds()),
      local_ip_(local_ip),
      local_port_(local_port) {
  if (host_ip.size() > 4)
      host_ip_ = base::inet_atob(host_ip);
  else
    host_ip_ = host_ip;
  if (local_ip.size() > 4)
      local_ip_ = base::inet_atob(local_ip);
  else
    local_ip_ = local_ip;
}

Contact::Contact()
    : node_id_(""),
      host_ip_(""),
      host_port_(0),
      failed_rpc_(0),
      rendezvous_ip_(""),
      rendezvous_port_(0),
      last_seen_(base::get_epoch_milliseconds()),
      local_ip_(""),
      local_port_(0) {}

Contact::Contact(const Contact&rhs)
    : node_id_(rhs.node_id_),
      host_ip_(rhs.host_ip_),
      host_port_(rhs.host_port_) ,
      failed_rpc_(rhs.failed_rpc_),
      rendezvous_ip_(rhs.rendezvous_ip_),
      rendezvous_port_(rhs.rendezvous_port_),
      last_seen_(rhs.last_seen_),
      local_ip_(rhs.local_ip_),
      local_port_(rhs.local_port_) {}

bool Contact::operator == (const Contact &other) {
  return static_cast<bool>((this->node_id() == other.node_id()) ||
                           ((this->host_ip() == other.host_ip()) &&
                           (this->host_port() == other.host_port())));
}

bool Contact::operator != (const Contact &other) {
  return static_cast<bool>((this->node_id() != other.node_id()) &&
                            ((this->host_ip() != other.host_ip()) ||
                            (this->host_port() != other.host_port())));
}

std::string Contact::ToString() {
  if (node_id_ == "" && host_port_ == 0 && host_ip_ == "") {
    return "Empty contact.\n";
  }
  std::string ser_contact("");
  std::string enc_id("");
  base::encode_to_hex(node_id_, enc_id);
  std::string port(base::itos(host_port_));
  ser_contact = "Node_id: " + enc_id + "\n";
  std::string dec_ip(base::inet_btoa(host_ip_));
  ser_contact += ("IP address: " + dec_ip + ":" + port + "\n");

  if (local_ip_ != "") {
    std::string dec_lip(base::inet_btoa(local_ip_));
    std::string lport(base::itos(local_port_));
    ser_contact += ("Local IP address: " + dec_lip + ":" + lport + "\n");
  }

  if (rendezvous_ip_ != "") {
    std::string dec_rip(base::inet_btoa(rendezvous_ip_));
    std::string rport(base::itos(rendezvous_port_));
    ser_contact += ("RV IP address: " + dec_rip + ":" + rport + "\n");
  }

  return ser_contact;
}

bool Contact::SerialiseToString(std::string *ser_output) {
  // do not serialise empty contacts
  if (node_id_ == "" && host_port_ == 0 && host_ip_ == "") {
    return false;
  }
  ContactInfo info;
  info.set_node_id(node_id_);
  info.set_ip(host_ip_);
  info.set_port(host_port_);
  info.set_rv_ip(rendezvous_ip_);
  info.set_rv_port(rendezvous_port_);
  info.set_local_ip(local_ip_);
  info.set_local_port(local_port_);
  info.SerializeToString(ser_output);
  return true;
}

bool Contact::ParseFromString(const std::string &data) {
  kad::ContactInfo info;
  if (!info.ParseFromString(data))
    return false;
  node_id_ = info.node_id();
  if (info.ip().size() > 4)
    host_ip_ = base::inet_atob(info.ip());
  else
    host_ip_ = info.ip();
  host_port_ = static_cast<boost::uint16_t>(info.port());
  if (info.has_rv_ip()) {
    if (info.rv_ip().size() > 4)
      rendezvous_ip_ = base::inet_atob(info.rv_ip());
    else
      rendezvous_ip_ = info.rv_ip();
    rendezvous_port_ = static_cast<boost::uint16_t>(info.rv_port());
  } else {
    rendezvous_ip_ = std::string("");
    rendezvous_port_ = 0;
  }
  if (info.has_local_ip()) {
    if (info.local_ip().size() > 4)
      local_ip_ = base::inet_atob(info.local_ip());
    else
      local_ip_ = info.local_ip();
    local_port_ = static_cast<boost::uint16_t>(info.local_port());
  } else {
    local_ip_ = std::string("");
    local_port_ = 0;
  }
  last_seen_ = base::get_epoch_milliseconds();
  return true;
}
}

