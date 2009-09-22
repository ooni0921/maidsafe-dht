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

#include "maidsafe/routingtable.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include "maidsafe/maidsafe-dht_config.h"

namespace base {

int PDRoutingTableHandler::GetTupleInfo(const std::string &kademlia_id,
  PDRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  *tuple = *it;
  return 0;
}

int PDRoutingTableHandler::GetTupleInfo(const std::string &host_ip,
    const boost::uint16_t &host_port, PDRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::iterator it = routingtable_.find(boost::make_tuple(host_ip,
                                                                   host_port));
  if (it == routingtable_.end())
    return 1;
  *tuple = *it;
  return 0;
}

int PDRoutingTableHandler::GetClosestRtt(
    const float &ideal_rtt,
    const std::set<std::string> &exclude_ids) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_rtt>::type& rtt_indx = routingtable_.get<t_rtt>();
  return 0;
}

int PDRoutingTableHandler::AddTuple(base::PDRoutingTableTuple tuple) {
  std::cout << "PDRoutingTableHandler::AddTuple -- waiting for lock" << std::endl;
  boost::mutex::scoped_lock guard(mutex_);
  std::cout << "PDRoutingTableHandler::AddTuple -- got lock" << std::endl;
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it =
      key_indx.find(tuple.kademlia_id());
  if (it == key_indx.end()) {
    key_indx.insert(tuple);
  } else {
    tuple.ctc_local_ = it->ctc_local_;
    if (tuple.rtt_ == 0)
      tuple.rtt_ = it->rtt_;
    key_indx.replace(it, tuple);
  }
  return 0;
}

int PDRoutingTableHandler::DeleteTupleByKadId(const std::string &kademlia_id) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  key_indx.erase(it);
  return 0;
}

int PDRoutingTableHandler::UpdateHostIp(const std::string &kademlia_id,
  const std::string &new_host_ip) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.host_ip_ = new_host_ip;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateHostPort(const std::string &kademlia_id,
  const boost::uint16_t &new_host_port) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.host_port_ = new_host_port;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateRendezvousIp(const std::string &kademlia_id,
  const std::string &new_rv_ip) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.rendezvous_ip_ = new_rv_ip;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateRendezvousPort(const std::string &kademlia_id,
  const boost::uint16_t &new_rv_port) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.rendezvous_port_ = new_rv_port;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdatePublicKey(const std::string &kademlia_id,
  const std::string &new_public_key) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.public_key_ = new_public_key;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateRtt(const std::string &kademlia_id,
  const float &new_rtt) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.rtt_ = new_rtt;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateRank(const std::string &kademlia_id,
  const boost::uint16_t &new_rank) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.rank_ = new_rank;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateSpace(const std::string &kademlia_id,
  const boost::uint32_t &new_space) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.space_ = new_space;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::ContactLocal(const std::string &kademlia_id) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 2;
  return it->ctc_local();
}

int PDRoutingTableHandler::UpdateContactLocal(const std::string &kademlia_id,
    const std::string &host_ip, const int &new_contact_local) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.host_ip_ = host_ip;
  new_tuple.ctc_local_ = new_contact_local;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PDRoutingTableHandler::UpdateLocalToUnknown(const std::string &ip,
                                                const boost::uint16_t &port) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::iterator it = routingtable_.find(boost::make_tuple(ip, port));
  if (it == routingtable_.end())
    return 1;
  PDRoutingTableTuple new_tuple = *it;
  new_tuple.ctc_local_ = kad::UNKNOWN;
  routingtable_.replace(it, new_tuple);
  return 0;
}

PDRoutingTable* PDRoutingTable::single = 0;
boost::mutex pdrt_mutex;

PDRoutingTable* PDRoutingTable::getInstance() {
  std::cout << "PDRoutingTable::getInstance" << std::endl;
  if (single == 0) {
    boost::mutex::scoped_lock lock(pdrt_mutex);
    if (single == 0)
      single = new PDRoutingTable();
  }
  std::cout << "returning instance of PDRoutingTable" << std::endl;
  return single;
}

boost::shared_ptr<PDRoutingTableHandler> PDRoutingTable::operator[] (
    const std::string &name) {
  std::cout << "PDRoutingTable operator []" << std::endl;
  std::map<std::string, boost::shared_ptr<PDRoutingTableHandler> >::iterator it;
  it = pdroutingtablehdls_.find(name);
  if (it == pdroutingtablehdls_.end()) {
    pdroutingtablehdls_.insert(std::pair<std::string,
        boost::shared_ptr<PDRoutingTableHandler> >(name,
        boost::shared_ptr<PDRoutingTableHandler>(new PDRoutingTableHandler)));
    std::cout << "Returning new instance of PDRoutingTableHandler" << std::endl;
    return pdroutingtablehdls_[name];
  }
  std::cout << "Returning instace of PDRoutingTableHandler" << std::endl;
  return it->second;
}
}  // namespace base
