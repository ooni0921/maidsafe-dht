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

#include "kademlia/datastore.h"

#include <exception>
#include "base/config.h"
#include "maidsafe/maidsafe-dht.h"

namespace kad {

DataStore::DataStore():db_(), is_open_(false) {
}

DataStore::~DataStore() {
  if (is_open_)
    Close();
}

bool DataStore::Init(const std::string &file_name,
    bool reuse_database) {
  try {
    // remove the old database file if it exists
//     if ((!reuse_database)&&(boost::filesystem::exists(file_name))){
//       remove(file_name_str.c_str());
//     }
    if (!boost::filesystem::exists(file_name)) {
      // create a new one
      db_.open(file_name.c_str());
      // create table structure
      db_.execDML("create table data(key blob, value blob, "
        "last_published_time integer, original_published_time integer, "
        "primary key(key, value));");
    } else {  // open it
      db_.open(file_name.c_str());
      if (!reuse_database) {
        // remove all data but status
        CppSQLite3Statement stmt;
        try {
          std::string key1("status");
          std::string key2("node_id");
          CppSQLite3Binary blob_key1;
          blob_key1.setBinary((const unsigned char*)key1.c_str(), key1.size());
          CppSQLite3Binary blob_key2;
          blob_key2.setBinary((const unsigned char*)key2.c_str(), key2.size());
          stmt = db_.compileStatement(
              "delete from data where key not in (?, ?);");
          stmt.bind(1, (const char*)blob_key1.getEncoded());
          stmt.bind(2, (const char*)blob_key2.getEncoded());
          stmt.execDML();
          stmt.reset();
          stmt.finalize();
        } catch(CppSQLite3Exception& e) {  // NOLINT
          stmt.reset();
          stmt.finalize();
      #ifdef DEBUG
          printf("%d : %s",  e.errorCode(), e.errorMessage());
      #endif
        }  // try statement
      }  // reuse database
    }
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    return false;
  }
  is_open_ = true;
  return true;
}

bool DataStore::Close() {
  bool result = true;
  try {
    db_.close();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    result = false;
  }
  is_open_ = false;
  return result;
}

bool DataStore::Keys(std::vector<std::string> *keys) {
  keys->clear();
  CppSQLite3Query qcpp;
  try {
    std::string s = "select distinct key from data;";
    qcpp = db_.execQuery(s.c_str());
    while (!qcpp.eof()) {
      CppSQLite3Binary blob_key;
      try {
        blob_key.setEncoded((unsigned char*)
          qcpp.fieldValue(static_cast<unsigned int>(0)));
        keys->push_back(std::string((const char*)blob_key.getBinary(),
            blob_key.getBinaryLength()));
      } catch(const std::exception& e) {
#ifdef DEBUG
        printf("%s", e.what());
#endif
        qcpp.nextRow();
        continue;
      }
      qcpp.nextRow();
    }
    qcpp.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
    qcpp.finalize();
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    return false;
  }
  return true;
}

inline bool DataStore::KeyValueExists(const std::string &key,
    const std::string &value) {
  bool result = false;
  CppSQLite3Statement stmt;
  CppSQLite3Query qcpp;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(),
        key.size());
    CppSQLite3Binary blob_value;
    blob_value.setBinary((const unsigned char*)value.c_str(),
        value.size());
    CppSQLite3Statement stmt = db_.compileStatement(
        "select count(*) from data where key=? and value=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    stmt.bind(2, (const char*)blob_value.getEncoded());
    qcpp = stmt.execQuery();
    if (1 <= qcpp.getIntField(0))
      result = true;
    qcpp.finalize();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
    qcpp.finalize();
    stmt.reset();
    stmt.finalize();
#ifdef DEBUG
      printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
  }
  return result;
}

inline bool DataStore::KeyExists(const std::string &key) {
  bool result = false;
  CppSQLite3Statement stmt;
  CppSQLite3Query qcpp;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(),
        key.size());
    stmt = db_.compileStatement(
        "select * from data where key=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    qcpp = stmt.execQuery();
    if (!qcpp.eof())
      result = true;
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
      printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
  }
  qcpp.finalize();
  stmt.reset();
  stmt.finalize();
  return result;
}

bool DataStore::StoreItem(const std::string &key,
    const std::string &value,
    boost::uint32_t last_published_time,
    boost::uint32_t original_published_time) {
#ifdef DEBUG
//  std::string hex_key;
//  base::encode_to_hex(key, hex_key);
//  printf("**************************************************\n");
//  printf("Value to insert in vault db: %s\n", hex_key.c_str());
//  printf("**************************************************\n");
//  std::string s;
//  std::cin >> s;
#endif
  // verify key&value
  if ((key.size() == 0) || (value.size() == 0) || (last_published_time <= 0)
      || (last_published_time <= 0)) {
    return false;
  }
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(),
        key.size());
    CppSQLite3Binary blob_value;
    blob_value.setBinary((const unsigned char*)value.c_str(),
        value.size());
    if (KeyValueExists(key, value)) {  // update last published time
      stmt = db_.compileStatement(
          "update data set last_published_time=? where key=? and value=?;");
      stmt.bind(1, static_cast<boost::int32_t>(last_published_time));
      stmt.bind(2, (const char*)blob_key.getEncoded());
      stmt.bind(3, (const char*)blob_value.getEncoded());
    } else {  // insert this key/value pair
      stmt = db_.compileStatement(
          "insert into data values(?, ?, ?, ?);");
      stmt.bind(1, (const char*)blob_key.getEncoded());
      stmt.bind(2, (const char*)blob_value.getEncoded());
      stmt.bind(3, static_cast<boost::int32_t>(last_published_time));
      stmt.bind(4, static_cast<boost::int32_t>(original_published_time));
    }
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
    stmt.reset();
    stmt.finalize();
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
      return false;
  }
  return true;
}

bool DataStore::LoadItem(const std::string &key,
    std::vector<std::string> &values) {
  values.clear();
  CppSQLite3Statement stmt;
  CppSQLite3Query qcpp;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(), key.size());
    stmt = db_.compileStatement("select value from data where key=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    qcpp = stmt.execQuery();
    while (!qcpp.eof()) {
      try {
        CppSQLite3Binary blob_value;
        blob_value.setEncoded((unsigned char*)
          qcpp.fieldValue(static_cast<unsigned int>(0)));
        values.push_back(std::string((const char*)blob_value.getBinary(),
            blob_value.getBinaryLength()));
      } catch(const std::exception& e) {
        qcpp.nextRow();
        continue;
      }
      qcpp.nextRow();
    }
    qcpp.finalize();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
    qcpp.finalize();
    stmt.reset();
    stmt.finalize();
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
      return false;
  }
  return true;
}

bool DataStore::DeleteKey(const std::string &key) {
  if (!KeyExists(key))
    return false;
  CppSQLite3Statement stmt;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(), key.size());
    stmt = db_.compileStatement("delete from data where key=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
    stmt.reset();
    stmt.finalize();
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    return false;
  }
  return true;
}

bool DataStore::DeleteItem(const std::string &key,
    const std::string &value) {
  bool result = false;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(),
        key.size());
    CppSQLite3Binary blob_value;
    blob_value.setBinary((const unsigned char*)value.c_str(),
        value.size());
    CppSQLite3Statement stmt;
    stmt = db_.compileStatement(
        "delete from data where key=? and value=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    stmt.bind(2, (const char*)blob_value.getEncoded());
    int n = stmt.execDML();
    if (n > 0)
      result = true;
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    return result;
  }
  return result;
}

bool DataStore::DeleteValue(const std::string &value) {
  bool result = false;
  try {
    CppSQLite3Binary blob_value;
    blob_value.setBinary((const unsigned char*)value.c_str(),
        value.size());
    CppSQLite3Statement stmt;
    stmt = db_.compileStatement(\
        "delete from data where value=?;");
    stmt.bind(1, (const char*)blob_value.getEncoded());
    int n = stmt.execDML();
    if (n > 0)
      result = true;
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    return result;
  }
  return result;
}

boost::uint32_t DataStore::DeleteExpiredValues() {
  CppSQLite3Statement stmt;
  try {
    boost::uint32_t now = base::get_epoch_time();
    stmt =
      db_.compileStatement("delete from data where last_published_time < ?;");
    stmt.bind(1, static_cast<boost::int32_t>(now -kExpireTime));
    stmt.execDML();
    stmt.reset();
    stmt.finalize();
  } catch(CppSQLite3Exception& e) {  // NOLINT
    stmt.reset();
    stmt.finalize();
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
    return false;
  }
  return true;
}

boost::uint32_t DataStore::LastPublishedTime(const std::string &key,
    const std::string &value) {
  boost::uint32_t result = -1;
  CppSQLite3Statement stmt;
  CppSQLite3Query qcpp;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(), key.size());
    CppSQLite3Binary blob_value;
    blob_value.setBinary((const unsigned char*)value.c_str(), value.size());
    stmt = db_.compileStatement(
        "select last_published_time from data where key=? and value=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    stmt.bind(2, (const char*)blob_value.getEncoded());
    qcpp = stmt.execQuery();
    if (!qcpp.eof())
      result = static_cast<boost::uint32_t>(qcpp.getIntField(0));
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
  }
  qcpp.finalize();
  stmt.reset();
  stmt.finalize();
  return result;
}

boost::uint32_t DataStore::OriginalPublishedTime(const std::string &key,
    const std::string &value) {
  boost::uint32_t result = -1;
  CppSQLite3Statement stmt;
  CppSQLite3Query qcpp;
  try {
    CppSQLite3Binary blob_key;
    blob_key.setBinary((const unsigned char*)key.c_str(), key.size());
    CppSQLite3Binary blob_value;
    blob_value.setBinary((const unsigned char*)value.c_str(), value.size());
    stmt = db_.compileStatement(
        "select original_published_time from data where key=? and value=?;");
    stmt.bind(1, (const char*)blob_key.getEncoded());
    stmt.bind(2, (const char*)blob_value.getEncoded());
    qcpp = stmt.execQuery();
    if (!qcpp.eof())
      result = static_cast<boost::uint32_t>(qcpp.getIntField(0));
  } catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%d : %s", e.errorCode(), e.errorMessage());
#endif
  }
  qcpp.finalize();
  stmt.reset();
  stmt.finalize();
  return result;
}

}  // namespace kad
