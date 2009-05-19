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

#include "base/routingtable.h"
#include <boost/filesystem.hpp>

namespace base {

int PDRoutingTableHandler::Connect(const std::string &db_name_) {
  try {
    db_ = new CppSQLite3DB();
    if (!boost::filesystem::exists(boost::filesystem::path(db_name_))) {
      // create a new one
      db_->open(db_name_.c_str());
      // create table structure
      if (CreateRoutingTableDb())
        return 1;
    } else {  // open it
      db_->open(db_name_.c_str());
    }
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%s - Connect Error %d : %s\n", db_name_.c_str(),
        e.errorCode(), e.errorMessage());
#endif
    delete db_;
    db_ = NULL;
    return 1;
  }
  return 0;
}

int PDRoutingTableHandler::Close() {
  try {
    db_->close();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("Close Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    delete db_;
    db_ = NULL;
    return 1;
  }
  delete db_;
  db_ = NULL;
  return 0;
}

int PDRoutingTableHandler::CreateRoutingTableDb() {
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
  try {
    // create table structure
    db_->execDML("create table routingtable(kad_id blob, "
      "host_ip char(15), host_port integer, "
      "rendezvous_ip char(15), rendezvous_port integer, "
      "public_key blob not null, rtt integer not null, rank integer not null, "
      "space integer not null, contact_local integer not null, "
      "primary key(kad_id));");
  } catch(CppSQLite3Exception &e) { // NOLINT
#ifdef DEBUG
      printf("Create Error %d : %s. DB: %s\n", e.errorCode(),
        e.errorMessage(), db_name_.c_str());
#endif
    return 1;
  }
  return 0;
}

int PDRoutingTableHandler::GetTupleInfo(const std::string &kademlia_id,
  PDRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement("select host_ip, host_port, "
      "rendezvous_ip, rendezvous_port,"
      "public_key, rtt, rank, space from routingtable where kad_id=?;");
    stmt.bind(1, (const char*)blob_id.getEncoded());
    CppSQLite3Query qcpp = stmt.execQuery();
    if (!qcpp.eof()) {
      std::string host_ip = qcpp.fieldValue(static_cast<unsigned int>(0));
      boost::uint16_t host_port =
        static_cast<boost::uint16_t>(qcpp.getIntField(1));
      std::string rendezvous_ip = qcpp.fieldValue(static_cast<unsigned int>(2));
      boost::uint16_t rendezvous_port =
        static_cast<boost::uint16_t>(qcpp.getIntField(3));
      CppSQLite3Binary blob_public_key;
      blob_public_key.setEncoded((unsigned char*)
        qcpp.fieldValue(static_cast<unsigned int>(4)));
      std::string public_key =
        std::string((const char*)blob_public_key.getBinary(),
                     blob_public_key.getBinaryLength());
      boost::uint32_t rtt =
        static_cast<boost::uint32_t>(qcpp.getIntField(5));
      boost::uint16_t rank =
        static_cast<boost::uint16_t>(qcpp.getIntField(6));
      boost::uint32_t space =
        static_cast<boost::uint32_t>(qcpp.getIntField(7));
      if (tuple == NULL) {
        Close();
        return 1;
      }
      *tuple = PDRoutingTableTuple(kademlia_id,
                                   host_ip,
                                   host_port,
                                   rendezvous_ip,
                                   rendezvous_port,
                                   public_key,
                                   rtt,
                                   rank,
                                   space);
      stmt.reset();
      stmt.finalize();
    } else {
      stmt.reset();
      stmt.finalize();
      Close();
      return 1;
    }
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
      printf("Select Error %d : %s. DB: %s\n", e.errorCode(),
        e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::GetTupleInfo(const std::string &host_ip,
    const boost::uint16_t &host_port, PDRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1) {
    return 1;
  }
  CppSQLite3Statement stmt;
  try {
    stmt = db_->compileStatement("select kad_id, "
      "rendezvous_ip, rendezvous_port,"
      "public_key, rtt, rank, space from routingtable "
      "where host_ip=? and host_port=?;");
    stmt.bind(1, host_ip.c_str());
    stmt.bind(2, host_port);
    CppSQLite3Query qcpp = stmt.execQuery();
    if (!qcpp.eof()) {
      CppSQLite3Binary blob_id;
      blob_id.setEncoded((unsigned char*)
        qcpp.fieldValue(static_cast<unsigned int>(0)));
      std::string kademlia_id =
        std::string((const char*)blob_id.getBinary(),
                     blob_id.getBinaryLength());
      std::string rendezvous_ip = qcpp.fieldValue(static_cast<unsigned int>(1));
      boost::uint16_t rendezvous_port =
        static_cast<boost::uint16_t>(qcpp.getIntField(2));
      CppSQLite3Binary blob_public_key;
      blob_public_key.setEncoded((unsigned char*)
        qcpp.fieldValue(static_cast<unsigned int>(3)));
      std::string public_key =
        std::string((const char*)blob_public_key.getBinary(),
                     blob_public_key.getBinaryLength());
      boost::uint32_t rtt =
        static_cast<boost::uint32_t>(qcpp.getIntField(4));
      boost::uint16_t rank =
        static_cast<boost::uint16_t>(qcpp.getIntField(5));
      boost::uint32_t space =
        static_cast<boost::uint32_t>(qcpp.getIntField(6));
      if (tuple == NULL) {
        Close();
        return 1;
      }
      *tuple = PDRoutingTableTuple(kademlia_id,
                                   host_ip,
                                   host_port,
                                   rendezvous_ip,
                                   rendezvous_port,
                                   public_key,
                                   rtt,
                                   rank,
                                   space);
      stmt.reset();
      stmt.finalize();
    } else {
      stmt.reset();
      stmt.finalize();
      Close();
      return 1;
    }
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("Select Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::AddTuple(const base::PDRoutingTableTuple &tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;

  bool insert = false;
  bool update = false;

  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)tuple.kademlia_id().c_str(),
        tuple.kademlia_id().size());
    stmt = db_->compileStatement("select host_ip, host_port, "
      "rendezvous_ip, rendezvous_port,"
      "public_key, rtt, rank, space from routingtable where kad_id=?;");
    stmt.bind(1, (const char*)blob_id.getEncoded());
    CppSQLite3Query qcpp = stmt.execQuery();
    if (!qcpp.eof()) {
      std::string host_ip = qcpp.fieldValue(static_cast<unsigned int>(0));
      boost::uint16_t host_port =
        static_cast<boost::uint16_t>(qcpp.getIntField(1));
      std::string rendezvous_ip = qcpp.fieldValue(static_cast<unsigned int>(2));
      boost::uint16_t rendezvous_port =
        static_cast<boost::uint16_t>(qcpp.getIntField(3));
      CppSQLite3Binary blob_public_key;
      blob_public_key.setEncoded((unsigned char*)
        qcpp.fieldValue(static_cast<unsigned int>(4)));
      std::string public_key =
        std::string((const char*)blob_public_key.getBinary(),
                     blob_public_key.getBinaryLength());
      boost::uint32_t rtt =
        static_cast<boost::uint32_t>(qcpp.getIntField(5));
      boost::uint16_t rank =
        static_cast<boost::uint16_t>(qcpp.getIntField(6));
      boost::uint32_t space =
        static_cast<boost::uint32_t>(qcpp.getIntField(7));
      if (tuple.host_ip() == host_ip && tuple.host_port() == host_port &&
          tuple.rendezvous_ip() == rendezvous_ip &&
          tuple.rendezvous_port() == rendezvous_port &&
          tuple.rtt() == rtt && tuple.rank() == rank &&
          tuple.space() == space && tuple.public_key() == public_key) {
        update = false;
      } else {
        update = true;
      }
    } else {
      insert = true;
    }
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
      printf("Select Error %d : %s. DB: %s\n", e.errorCode(),
        e.errorMessage(), db_name_.c_str());
#endif
      stmt.reset();
      stmt.finalize();
      Close();
      return 1;
  }

  if (insert) {
    CppSQLite3Statement stmt;
    try {
      CppSQLite3Binary blob_id;
      blob_id.setBinary((const unsigned char*)tuple.kademlia_id().c_str(),
          tuple.kademlia_id().size());
      CppSQLite3Binary blob_public_key;
      blob_public_key.setBinary((
          const unsigned char*)tuple.public_key().c_str(),
          tuple.public_key().size());
      CppSQLite3Statement stmt;
      stmt = db_->compileStatement(
          "insert into routingtable values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
      stmt.bind(1, (const char*)blob_id.getEncoded());
      stmt.bind(2, tuple.host_ip().c_str());
      stmt.bind(3, tuple.host_port());
      stmt.bind(4, tuple.rendezvous_ip().c_str());
      stmt.bind(5, tuple.rendezvous_port());
      stmt.bind(6, (const char*)blob_public_key.getEncoded());
      stmt.bind(7, static_cast<boost::int32_t>(tuple.rtt()));
      stmt.bind(8, static_cast<boost::int32_t>(tuple.rank()));
      stmt.bind(9, static_cast<boost::int32_t>(tuple.space()));
      stmt.bind(10, static_cast<boost::int32_t>(2));
      stmt.execDML();
      stmt.reset();
      stmt.finalize();
      Close();
      return 0;
    } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
      printf("Add Error %d : %s. DB: %s\n", e.errorCode(),
        e.errorMessage(), db_name_.c_str());
#endif
      stmt.reset();
      stmt.finalize();
      Close();
      return 1;
    }
  }
  // Do an update
  if (update) {
    CppSQLite3Statement stmt;
    try {
      CppSQLite3Binary blob_id;
      blob_id.setBinary((const unsigned char*)tuple.kademlia_id().c_str(),
          tuple.kademlia_id().size());
      CppSQLite3Binary blob_public_key;
      blob_public_key.setBinary(
          (const unsigned char*)tuple.public_key().c_str(),
          tuple.public_key().size());
      stmt = db_->compileStatement(
          "update routingtable set host_ip=?, host_port=?, rendezvous_ip=?, "
          "rendezvous_port=?, public_key=?, rtt=?, rank=?, space=? where "
          "kad_id=?;");
      stmt.bind(1, tuple.host_ip().c_str());
      stmt.bind(2, tuple.host_port());
      stmt.bind(3, tuple.rendezvous_ip().c_str());
      stmt.bind(4, tuple.rendezvous_port());
      stmt.bind(5, (const char*)blob_public_key.getEncoded());
      stmt.bind(6, static_cast<boost::int32_t>(tuple.rtt()));
      stmt.bind(7, static_cast<boost::int32_t>(tuple.rank()));
      stmt.bind(8, static_cast<boost::int32_t>(tuple.space()));
      stmt.bind(9, (const char*)blob_id.getEncoded());
      stmt.execDML();
      stmt.reset();
      stmt.finalize();
    } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
      printf("Update Error %d : %s. DB: %s\n", e.errorCode(),
        e.errorMessage(), db_name_.c_str());
#endif
      stmt.reset();
      stmt.finalize();
      Close();
      return 1;
    }
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::DeleteTupleByKadId(const std::string &kademlia_id) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    CppSQLite3Statement stmt;
    stmt = db_->compileStatement(
        "delete from routingtable where kad_id=?;");
    stmt.bind(1, (const char*)blob_id.getEncoded());
    int del_rows = stmt.execDML();
    stmt.reset();
    stmt.finalize();
    if (del_rows == 0) {
      Close();
      return 1;
    }
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("Delete Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateHostIp(const std::string &kademlia_id,
  const std::string &new_host_ip) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set host_ip=? where kad_id=?;");
    stmt.bind(1, new_host_ip.c_str());
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateHostIp Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateHostPort(const std::string &kademlia_id,
  const boost::uint16_t &new_host_port) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set host_port=? where kad_id=?;");
    stmt.bind(1, new_host_port);
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateHostPort Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateRendezvousIp(const std::string &kademlia_id,
  const std::string &new_rv_ip) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set rendezvous_ip=? where kad_id=?;");
    stmt.bind(1, new_rv_ip.c_str());
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateRzIp Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateRendezvousPort(const std::string &kademlia_id,
  const boost::uint16_t &new_rv_port) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set rendezvous_port=? where kad_id=?;");
    stmt.bind(1, new_rv_port);
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateRzPort Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdatePublicKey(const std::string &kademlia_id,
  const std::string &new_public_key) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    CppSQLite3Binary blob_public_key;
    blob_public_key.setBinary((const unsigned char*)new_public_key.c_str(),
        new_public_key.size());
    stmt = db_->compileStatement(
        "update routingtable set public_key=? where kad_id=?;");
    stmt.bind(1, (const char*)blob_public_key.getEncoded());
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdatePublicKey Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateRtt(const std::string &kademlia_id,
  const boost::uint32_t &new_rtt) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set rtt=? where kad_id=?;");
    stmt.bind(1, static_cast<boost::int32_t>(new_rtt));
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateRtt Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateRank(const std::string &kademlia_id,
  const boost::uint16_t &new_rank) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set rank=? where kad_id=?;");
    stmt.bind(1, new_rank);
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateRank Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::UpdateSpace(const std::string &kademlia_id,
  const boost::uint32_t &new_space) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set space=? where kad_id=?;");
    stmt.bind(1, static_cast<boost::int32_t>(new_space));
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateSpace Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

int PDRoutingTableHandler::ContactLocal(const std::string &kademlia_id) {
  boost::mutex::scoped_lock guard(mutex_);
  int contact_local = 2;
  if (Connect(db_name_) == 1)
    return contact_local;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement("select contact_local "
      "from routingtable where kad_id=?;");
    stmt.bind(1, (const char*)blob_id.getEncoded());
    CppSQLite3Query qcpp = stmt.execQuery();
    if (!qcpp.eof())
      contact_local = qcpp.getIntField(0);
    stmt.reset();
    stmt.finalize();
    Close();
    return contact_local;
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("Select Error %d : %s. DB: %s\n", e.errorCode(), e.errorMessage(),
      db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return contact_local;
  }
}

int PDRoutingTableHandler::UpdateContactLocal(const std::string &kademlia_id,
  const int &new_contact_local) {
  boost::mutex::scoped_lock guard(mutex_);
  if (Connect(db_name_) == 1)
    return 1;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_id;
    blob_id.setBinary((const unsigned char*)kademlia_id.c_str(),
        kademlia_id.size());
    stmt = db_->compileStatement(
        "update routingtable set contact_local=? where kad_id=?;");
    stmt.bind(1, static_cast<boost::int32_t>(new_contact_local));
    stmt.bind(2, (const char*)blob_id.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("UpdateContactLocal Error %d : %s. DB: %s\n", e.errorCode(),
      e.errorMessage(), db_name_.c_str());
#endif
    stmt.reset();
    stmt.finalize();
    Close();
    return 1;
  }
  Close();
  return 0;
}

}  // namespace base
