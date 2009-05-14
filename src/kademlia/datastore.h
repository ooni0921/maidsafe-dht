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
 *  Created on: Jul 29, 2008
 *      Author: haiyang
 */

#ifndef KADEMLIA_DATASTORE_H_
#define KADEMLIA_DATASTORE_H_

#include <boost/filesystem.hpp>
#include <boost/cstdint.hpp>
#include <string>
#include <vector>
#include "base/cppsqlite3.h"

namespace kad {
// This class implements physical storage (for data published and fetched via
// the RPCs) for the Kademlia DHT. SQLite database will be used as the
// database.
class DataStore {
 public:
  DataStore();
  ~DataStore();
  // Initiate the data store, creating and connecting to the database.
  // file_name is the path of the data file. reuse_database is the flag for
  // whether to the data file or not. Return true operation succeeds.
  // Database table should contains: key, value, type, last_published_time,
  // original_published_time. primary key(key, value)
  bool Init(const std::string &file_name,
      bool reuse_database = false);
  bool Close();
  // Return all the keys in the database, the keys should be unique
  bool Keys(std::vector<std::string> &keys);  //NOLINT
  // Store the key, value pair into the database
  bool StoreItem(const std::string &key,
      const std::string &value,
      boost::uint32_t last_published_time,
      boost::uint32_t original_published_time);
  // Return a vector of values under the key
  bool LoadItem(const std::string &key, std::vector<std::string> &values);
  // Delete all key/values under the key
  bool DeleteKey(const std::string &key);
  // Delete a record specified by key/value
  bool DeleteItem(const std::string &key, const std::string &value);
  // Delete all records containing the value
  bool DeleteValue(const std::string &value);
  boost::uint32_t DeleteExpiredValues();
  // Return the oldest time of all the records under the key.
  // Time format is the seconds since Epoch(1970.1.1)
  boost::uint32_t LastPublishedTime(const std::string &key,
      const std::string &value);
  boost::uint32_t OriginalPublishedTime(const std::string &key,
      const std::string &value);
 private:
  CppSQLite3DB db_;
  bool is_open_;
  inline bool KeyValueExists(const std::string &key, const std::string &value);
};
}  // namespace kad
#endif  // KADEMLIA_DATASTORE_H_
