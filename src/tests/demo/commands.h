/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for base/calllatertimer.cc
* Version:      1.0
* Created:      2009-06-12-02.54.48
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef TESTS_DEMO_COMMANDS_H_
#define TESTS_DEMO_COMMANDS_H_

#include <boost/function.hpp>
#include <string>
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/crypto.h"

namespace kad {
class KNode;
}

namespace kaddemo {

class Commands {
 public:
  Commands(kad::KNode *node, const boost::uint16_t &K);
  void Run();
 private:
  void FindValueCallback(const std::string &result, const std::string &key,
     const bool &write_to_file, const std::string &path);
  void StoreCallback(const std::string &result, const std::string &key,
      const boost::uint32_t &ttl);
  void PingCallback(const std::string &result, const std::string &id);
  void FindNodeCallback(const std::string &result, const std::string &id);
  void ProcessCommand(const std::string &cmdline, bool *wait_for_cb);
  void PrintUsage();
  bool ReadFile(const std::string &path, std::string *content);
  void WriteToFile(const std::string &path, const std::string &content);
  void Store50Values(const std::string &prefix);
  void Store50Callback(const std::string &result, const std::string &key,
      bool *arrived);
  kad::KNode *node_;
  bool result_arrived_;
  double min_succ_stores_;
  crypto::Crypto cryobj_;
  bool finish_;
};

}  // namespace

#endif  // TESTS_DEMO_COMMANDS_H_
