/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef BASE_ROUTINGTABLE_H_
#define BASE_ROUTINGTABLE_H_
#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/thread/mutex.hpp>
#ifdef WIN32
#include <shlobj.h>
#endif
#include <string>
#include "base/cppsqlite3.h"
#include "base/utils.h"
#include "base/singleton.h"

namespace base {

class PDRoutingTableTuple {
 private:
  std::string kademlia_id_;
  std::string host_ip_;
  boost::uint16_t host_port_;
  std::string rendezvous_ip_;
  boost::uint16_t rendezvous_port_;
  std::string public_key_;
  boost::uint32_t rtt_;
  boost::uint16_t rank_;
  boost::uint32_t space_;

 public:
  // Fill the constructor as needed
  PDRoutingTableTuple()
    :kademlia_id_(),
     host_ip_(),
     host_port_(0),
     rendezvous_ip_(),
     rendezvous_port_(0),
     public_key_(),
     rtt_(0),
     rank_(0),
     space_(0) {}
  PDRoutingTableTuple(const std::string &kademlia_id,
                      const std::string &host_ip,
                      const boost::uint16_t &host_port,
                      const std::string &rendezvous_ip,
                      const boost::uint16_t &rendezvous_port,
                      const std::string &public_key,
                      const boost::uint32_t &rtt,
                      const boost::uint16_t &rank,
                      const boost::uint32_t &space)
    :kademlia_id_(kademlia_id),
     host_ip_(host_ip),
     host_port_(host_port),
     rendezvous_ip_(rendezvous_ip),
     rendezvous_port_(rendezvous_port),
     public_key_(public_key),
     rtt_(rtt),
     rank_(rank),
     space_(space) {}
  PDRoutingTableTuple(const PDRoutingTableTuple &tuple)
    :kademlia_id_(tuple.kademlia_id()),
      host_ip_(tuple.host_ip()),
     host_port_(tuple.host_port()),
     rendezvous_ip_(tuple.rendezvous_ip()),
     rendezvous_port_(tuple.rendezvous_port()),
     public_key_(tuple.public_key()),
     rtt_(tuple.rtt()),
     rank_(tuple.rank()),
     space_(tuple.space()) {}
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
    return *this; }
  const std::string kademlia_id() const { return kademlia_id_; }
  const std::string host_ip() const { return host_ip_; }
  boost::uint16_t host_port() const { return host_port_; }
  const std::string rendezvous_ip() const { return rendezvous_ip_; }
  boost::uint16_t rendezvous_port() const { return rendezvous_port_; }
  const std::string public_key() const { return public_key_; }
  boost::uint32_t rtt() const { return rtt_; }
  boost::uint16_t rank() const { return rank_; }
  boost::uint32_t space() const { return space_; }
};

class PDRoutingTableHandler {
 public:
  explicit PDRoutingTableHandler(const std::string& db_name = "")
  : db_(NULL), db_name_(db_name), mutex_() {
    // TODO(Fraser#5#): 2009-04-24 - This is repeated code - move to base?
    boost::filesystem::path app_path("");
#if defined(MAIDSAFE_POSIX)
    app_path = boost::filesystem::path("/var/cache/maidsafe/",
      boost::filesystem::native);
#elif defined(MAIDSAFE_WIN32)
    TCHAR szpth[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_COMMON_APPDATA,
                                  NULL,
                                  0,
                                  szpth))) {
      std::ostringstream stm;
      const std::ctype<char> &ctfacet =
          std::use_facet< std::ctype<char> >(stm.getloc());
      for (size_t i = 0; i < wcslen(szpth); ++i)
        stm << ctfacet.narrow(szpth[i], 0);
      app_path = boost::filesystem::path(stm.str(), boost::filesystem::native);
      app_path /= "maidsafe";
    }
#elif defined(MAIDSAFE_APPLE)
    app_path = boost::filesystem::path("/Library/maidsafe/", fs::native);
#endif
    boost::filesystem::path db_path = app_path;
    if (db_name_.size())
      db_path /= db_name_;
    else
      db_path /= "RoutingTable.db";
    db_name_ = db_path.string();
    // Connect(db_name_);
  }
  ~PDRoutingTableHandler() {
      // Close();
  }
  void Clear() {
    scoped_lock guard(mutex_);
    try {
      if (boost::filesystem::exists(boost::filesystem::path(db_name_))) {
        boost::filesystem::remove(db_name_);
      }
    } catch(std::exception &) {}
  }
  int GetTupleInfo(const std::string &kademlia_id, PDRoutingTableTuple *tuple);
  int GetTupleInfo(const std::string &host_ip,
                   const boost::uint16_t &host_port,
                   PDRoutingTableTuple *tuple);
  int AddTuple(const base::PDRoutingTableTuple &tuple);
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
    const boost::uint32_t &new_rtt);
  int UpdateRank(const std::string &kademlia_id,
    const boost::uint16_t &new_rank);
  int UpdateSpace(const std::string &kademlia_id,
    const boost::uint32_t &new_space);
  int ContactLocal(const std::string &kademlia_id);
  int UpdateContactLocal(const std::string &kademlia_id,
    const int &new_contact_local);
 private:
  PDRoutingTableHandler(const PDRoutingTableHandler&);
  PDRoutingTableHandler &operator=(const PDRoutingTableHandler &);
  int Connect(const std::string &db_name_);
  int Close();
  // This is the DB structure that is needed.
  /****************************************
  create table pdroutingtable(
    kad_id char(64) primary key,
    rendezvous_ip int,
    rendezvous_port int,
    public_key char(512) not null,
    int rtt not null,
    int rank not null,
    int space not null
  );
  ****************************************/
  int CreateRoutingTableDb();
  CppSQLite3DB *db_;
  std::string db_name_;
  boost::mutex mutex_;
};

// typedef Singleton<PDRoutingTableHandler> PDRoutingTable;
}

#endif  // BASE_ROUTINGTABLE_H_
