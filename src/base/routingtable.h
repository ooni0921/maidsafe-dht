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

#ifndef BASE_ROUTINGTABLE_H_
#define BASE_ROUTINGTABLE_H_
#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>

#ifdef WIN32
#include <shlobj.h>
#endif
#include <string>
#include <map>
#include <functional>


namespace base {

struct PDRoutingTableTuple {
  std::string kademlia_id_, host_ip_, rendezvous_ip_, public_key_;
  boost::uint16_t host_port_, rendezvous_port_, rank_;
  float rtt_;
  boost::uint32_t space_;
  int ctc_local_;

  // Fill the constructor as needed
  PDRoutingTableTuple() : kademlia_id_(), host_ip_(), rendezvous_ip_(),
      public_key_(), host_port_(0), rendezvous_port_(0), rank_(0), rtt_(0),
     space_(0), ctc_local_(2) {}
  PDRoutingTableTuple(const std::string &kademlia_id,
      const std::string &host_ip, const boost::uint16_t &host_port,
      const std::string &rendezvous_ip, const boost::uint16_t &rendezvous_port,
      const std::string &public_key, const float &rtt,
      const boost::uint16_t &rank, const boost::uint32_t &space)
    : kademlia_id_(kademlia_id), host_ip_(host_ip),
      rendezvous_ip_(rendezvous_ip), public_key_(public_key),
      host_port_(host_port), rendezvous_port_(rendezvous_port), rank_(rank),
      rtt_(rtt), space_(space), ctc_local_(2) {}
  PDRoutingTableTuple(const PDRoutingTableTuple &tuple)
    : kademlia_id_(tuple.kademlia_id()), host_ip_(tuple.host_ip()),
      rendezvous_ip_(tuple.rendezvous_ip()), public_key_(tuple.public_key()),
      host_port_(tuple.host_port()), rendezvous_port_(tuple.rendezvous_port()),
      rank_(tuple.rank()), rtt_(tuple.rtt()), space_(tuple.space()),
      ctc_local_(tuple.ctc_local_) {}
  PDRoutingTableTuple& operator=(const PDRoutingTableTuple &tuple) {
    kademlia_id_ = tuple.kademlia_id();
    host_ip_ = tuple.host_ip();
    host_port_ = tuple.host_port();
    rendezvous_ip_ = tuple.rendezvous_ip();
    rendezvous_port_ = tuple.rendezvous_port();
    public_key_ = tuple.public_key();
    rtt_ = tuple.rtt();
    rank_ = tuple.rank();
    space_ = tuple.space();
    ctc_local_ = tuple.ctc_local();
    return *this; }
  const std::string kademlia_id() const { return kademlia_id_; }
  const std::string host_ip() const { return host_ip_; }
  boost::uint16_t host_port() const { return host_port_; }
  const std::string rendezvous_ip() const { return rendezvous_ip_; }
  boost::uint16_t rendezvous_port() const { return rendezvous_port_; }
  const std::string public_key() const { return public_key_; }
  float rtt() const { return rtt_; }
  boost::uint16_t rank() const { return rank_; }
  boost::uint32_t space() const { return space_; }
  int ctc_local() const { return ctc_local_; }
};

/* Tags */
struct t_key {};
struct t_ip {};
struct t_port {};
struct t_rtt {};
struct t_rank {};

typedef boost::multi_index::multi_index_container<
  PDRoutingTableTuple,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<t_key>,
      BOOST_MULTI_INDEX_MEMBER(PDRoutingTableTuple, std::string, kademlia_id_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_ip>,
      BOOST_MULTI_INDEX_MEMBER(PDRoutingTableTuple, std::string, host_ip_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_port>,
      BOOST_MULTI_INDEX_MEMBER(PDRoutingTableTuple, boost::uint16_t, host_port_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_rtt>,
      BOOST_MULTI_INDEX_MEMBER(PDRoutingTableTuple, float, rtt_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_rank>,
      BOOST_MULTI_INDEX_MEMBER(PDRoutingTableTuple, boost::uint16_t, rank_),
      std::greater<boost::uint16_t>
    >
  >
> routingtable;

class PDRoutingTableHandler {
 public:
  PDRoutingTableHandler() : routingtable_(), mutex_() {}
  void Clear() {
    boost::mutex::scoped_lock guard(mutex_);
    routingtable_.clear();
  }
  int GetTupleInfo(const std::string &kademlia_id, PDRoutingTableTuple *tuple);
  int GetTupleInfo(const std::string &host_ip,
                   const boost::uint16_t &host_port,
                   PDRoutingTableTuple *tuple);
  int AddTuple(base::PDRoutingTableTuple tuple);
  int DeleteTupleByKadId(const std::string &kademlia_id);
  int UpdateHostIp(const std::string &kademlia_id,
    const std::string &new_host_ip);
  int UpdateHostPort(const std::string &kademlia_id,
    const boost::uint16_t &new_host_port);
  int UpdateRendezvousIp(const std::string &kademlia_id,
    const std::string &new_rv_ip);
  int UpdateRendezvousPort(const std::string &kademlia_id,
    const boost::uint16_t &new_rv_port);
  int UpdatePublicKey(const std::string &kademlia_id,
    const std::string &new_public_key);
  int UpdateRtt(const std::string &kademlia_id,
    const float &new_rtt);
  int UpdateRank(const std::string &kademlia_id,
    const boost::uint16_t &new_rank);
  int UpdateSpace(const std::string &kademlia_id,
    const boost::uint32_t &new_space);
  int ContactLocal(const std::string &kademlia_id);
  int UpdateContactLocal(const std::string &kademlia_id,
    const int &new_contact_local);
 private:
//  PDRoutingTableHandler(const PDRoutingTableHandler&);
  PDRoutingTableHandler &operator=(const PDRoutingTableHandler &);
  routingtable routingtable_;
  boost::mutex mutex_;
};

class PDRoutingTable {
 public:
  static PDRoutingTable& getInstance();
  boost::shared_ptr<PDRoutingTableHandler> operator[] (const std::string &name);
 private:
  PDRoutingTable() : pdroutingtablehdls_() {}
  explicit PDRoutingTable(PDRoutingTable const&);
  void operator=(PDRoutingTable const&);
  std::map< std::string, boost::shared_ptr<PDRoutingTableHandler> >
      pdroutingtablehdls_;
};

// typedef Singleton<PDRoutingTableHandler> PDRoutingTable;
}

#endif  // BASE_ROUTINGTABLE_H_
