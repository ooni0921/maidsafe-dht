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

#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/thread.hpp>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>
#include "tests/demo/commands.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/maidsafe-dht.h"


namespace kaddemo {

Commands::Commands(kad::KNode *node, const boost::uint16_t &K)
      : node_(node), result_arrived_(false),
        min_succ_stores_(K * kad::kMinSuccessfulPecentageStore), cryobj_(),
        finish_(false) {
  cryobj_.set_hash_algorithm(crypto::SHA_512);
}

void Commands::Run() {
  PrintUsage();
  bool wait = false;
  boost::mutex wait_mutex;
  while (!finish_) {
    std::cout << "demo > ";
    std::string cmdline;
    std::getline(std::cin, cmdline);
    ProcessCommand(cmdline, &wait);
    if (wait) {
      while (!result_arrived_)
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
      result_arrived_ = false;
    }
  }
}

void Commands::StoreCallback(const std::string &result,
    const std::string &key, const boost::uint32_t &ttl) {
  kad::StoreResponse msg;
  std::string enc_key;
  base::encode_to_hex(key, &enc_key);
  if (!msg.ParseFromString(result)) {
    printf("ERROR. Invalid response. Kademlia Store Value key %s\n",
        enc_key.c_str());
    result_arrived_ = true;
    return;
  }
  if (msg.result() != kad::kRpcResultSuccess) {
    printf("Failed to store %f copies of values for key %s.\n",
        min_succ_stores_, enc_key.c_str());
    printf("Some copies might have been stored\n");
  } else {
    printf("Successfully stored key %s with ttl %d\n", enc_key.c_str(), ttl);
  }
  result_arrived_ = true;
}

void Commands::PingCallback(const std::string &result, const std::string &id) {
  kad::PingResponse msg;
  std::string enc_id;
  base::encode_to_hex(id, &enc_id);
  if (!msg.ParseFromString(result)) {
    printf("ERROR. Invalid response. Kademlia Ping Node to node with id %s\n",
        enc_id.c_str());
    result_arrived_ = true;
    return;
  }
  if (msg.result() != kad::kRpcResultSuccess) {
    printf("Node with id %s is down.\n", enc_id.c_str());
  } else {
    printf("Node with id %s is up.\n", enc_id.c_str());
  }
  result_arrived_ = true;
}

void Commands::FindNodeCallback(const std::string &result,
      const std::string &id) {
  kad::FindNodeResult msg;
  std::string enc_id;
  base::encode_to_hex(id, &enc_id);
  if (!msg.ParseFromString(result)) {
    printf("ERROR. Invalid Response. Kademlia Find Node to node with id %s\n",
        enc_id.c_str());
    result_arrived_ = true;
    return;
  }
  if (msg.result() != kad::kRpcResultSuccess) {
    printf("Could not find node with id %s.\n", enc_id.c_str());
  } else {
    kad::Contact ctc;
    if (!msg.has_contact() || !ctc.ParseFromString(msg.contact()))
      printf("Could not find node with id %s.\n", enc_id.c_str());
    else
      printf("Node with id %s found. Node info:\n=%s", enc_id.c_str(),
          ctc.ToString().c_str());
  }
  result_arrived_ = true;
}

void Commands::FindValueCallback(const std::string &result,
       const std::string &key, const bool &write_to_file,
       const std::string &path) {
  kad::FindResponse msg;
  std::string enc_key;
  base::encode_to_hex(key, &enc_key);
  if (!msg.ParseFromString(result)) {
    printf("ERROR.  Invalid response. Kademlia Load Value key %s\n",
        enc_key.c_str());
    result_arrived_ = true;
    return;
  }
  if (msg.result() != kad::kRpcResultSuccess || msg.values_size() == 0) {
    printf("There is no value stored under key %s\n", enc_key.c_str());
  } else {
    printf("Successfully retrieved value(s) for key %s\n", enc_key.c_str());
    if (write_to_file) {
      // we only write to file the first value
      WriteToFile(path, msg.values(0));
    } else {
      printf("Values found for key %s\n", enc_key.c_str());
      for (int i = 0; i < msg.values_size(); i++)
        printf("%d.  %s\n", i+1, msg.values(i).c_str());
    }
  }
  result_arrived_ = true;
}

bool Commands::ReadFile(const std::string &path, std::string *content) {
  *content = "";
  if (!boost::filesystem::exists(path) ||
      boost::filesystem::is_directory(path)) {
    printf("%s does not exist or is a directory\n", path.c_str());
    return false;
  }
  try {
    boost::filesystem::ifstream fin;
    boost::uint64_t size = boost::filesystem::file_size(path);
    if (size == 0) {
      printf("File %s is empty\n", path.c_str());
    }
    fin.open(path, std::ios_base::in | std::ios::binary);
    if (fin.eof() || !fin.is_open()) {
      printf("Can not open file %s\n", path.c_str());
      return false;
    }
    char *temp = new char[size];
    fin.read(temp, size);
    fin.close();
    *content = std::string(temp, size);
    delete temp;
  }
  catch(const std::exception &ex) {
    printf("Error reading from file %s: %s\n", path.c_str(), ex.what());
    return false;
  }
  return true;
}

void Commands::WriteToFile(const std::string &path,
      const std::string &content) {
  try {
    boost::filesystem::ofstream fout;
    fout.open(path, std::ios_base::out | std::ios::binary);
    fout.write(content.c_str(), content.size());
    fout.close();
  }
  catch(const std::exception &ex) {
    printf("Error writing to file %s: %s\n", path.c_str(), ex.what());
  }
}

void Commands::PrintUsage() {
  printf("\thelp                        Print help.\n");
  printf("\tgetinfo                     Print this node's info.\n");
  printf("\tpingnode node_id            Ping node with id node_id.\n");
  printf("\tfindnode node_id            Find node with id node_id.\n");
  printf("\tstorefile key filepath ttl  Store contents of file in the network");
  printf(".  ttl in minutes.\n");
  printf("\tstorevalue key value ttl    Store value in the network. ");
  printf("ttl in minutes.\n");
  printf("\tfindfile key filepath       Find value stored with key and save ");
  printf("it to filepath.\n");
  printf("\tfindvalue key               Find value stored with key.\n");
  printf("\tstore50values prefix        Store 50 key value pairs of for ");
  printf("(prefix[i],prefix[i]*100.\n");
  printf("\texit                        Stop the node and exit.\n");
  printf("\n\tNOTE -- node_id should be input encoded.\n");
  printf("\t          If key is not a valid 512 hash key (encoded format),\n");
  printf("\t          it will be hashed.\n\n");
 }

void Commands::ProcessCommand(const std::string &cmdline, bool *wait_for_cb) {
  std::string cmd;
  std::vector<std::string> args;
  try {
    boost::char_separator<char> sep(" ");
    boost::tokenizer< boost::char_separator<char> > tok(cmdline, sep);
    for (boost::tokenizer< boost::char_separator<char> >::iterator
         it = tok.begin(); it != tok.end(); ++it) {
      if (it == tok.begin())
        cmd = *it;
      else
        args.push_back(*it);
    }
  }
  catch(std::exception &ex) {
    printf("Error processing command: %s\n", ex.what());
    *wait_for_cb = false;
    return;
  }

  if (cmd == "storefile") {
    std::string content;
    if (args.size() != 3) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for storefile command\n");
    } else if (!ReadFile(args[1], &content)){
      *wait_for_cb = false;
    } else {
      boost::uint32_t ttl = boost::lexical_cast<boost::uint32_t>(args[2]);
      std::string key;
      if (args[0].size() != 128 || !base::decode_from_hex(args[0], &key))
        key = cryobj_.Hash(args[0], "", crypto::STRING_STRING, false);
      node_->StoreValue(key, content, ttl*60, boost::bind(
          &Commands::StoreCallback, this, _1, key, ttl));
      *wait_for_cb = true;
    }
  } else if (cmd == "storevalue") {
    if (args.size() != 3) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for storevalue command\n");
    } else {
      boost::uint32_t ttl = base::stoi(args[2]);
      std::string key;
      if (args[0].size() != 128 || !base::decode_from_hex(args[0], &key))
        key = cryobj_.Hash(args[0], "", crypto::STRING_STRING, false);
      node_->StoreValue(key, args[1], ttl*60, boost::bind(
          &Commands::StoreCallback, this, _1, key, ttl));
      *wait_for_cb = true;
    }
  } else if (cmd == "findvalue") {
    if (args.size() != 1) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for findvalue command\n");
    } else {
      std::string key;
      if (args[0].size() != 128 || !base::decode_from_hex(args[0], &key))
        key = cryobj_.Hash(args[0], "", crypto::STRING_STRING, false);
      node_->FindValue(key, false,
          boost::bind(&Commands::FindValueCallback, this, _1, key, false, ""));
      *wait_for_cb = true;
    }
  } else if (cmd == "findfile") {
    if (args.size() != 2) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for findfile command\n");
    } else {
      std::string key;
      if (args[0].size() != 128 || !base::decode_from_hex(args[0], &key))
        key = cryobj_.Hash(args[0], "", crypto::STRING_STRING, false);
      node_->FindValue(key, false,
          boost::bind(&Commands::FindValueCallback, this, _1, key, true,
          args[1]));
      *wait_for_cb = true;
    }
  } else if (cmd == "findnode") {
    if (args.size() != 1) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for findnode command\n");
    } else {
      std::string key;
      if (args[0].size() == 128 && base::decode_from_hex(args[0], &key)) {
        node_->FindNode(key, boost::bind(&Commands::FindNodeCallback, this, _1,
            key), false);
        *wait_for_cb = true;
      } else {
        printf("Invalid Node id\n");
        *wait_for_cb = false;
      }
    }
  } else if (cmd == "pingnode") {
    if (args.size() != 1) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for pingnode command\n");
    } else {
      std::string key;
      if (args[0].size() == 128 && base::decode_from_hex(args[0], &key)) {
        node_->Ping(key, boost::bind(&Commands::PingCallback, this, _1,
            key));
        *wait_for_cb = true;
      } else {
        printf("Invalid Node id\n");
        *wait_for_cb = false;
      }
    }
  } else if (cmd == "getinfo") {
    kad::Contact ctc(node_->contact_info());
    printf("Node info:\n, %s", ctc.ToString().c_str());
    *wait_for_cb = false;
  } else if (cmd == "help") {
    PrintUsage();
    *wait_for_cb = false;
  } else if (cmd == "exit") {
    printf("Exiting application...\n");
    finish_ = true;
    *wait_for_cb = false;
  } else if (cmd == "store50values") {
    if (args.size() != 1) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for store50values command\n");
    } else {
      Store50Values(args[0]);
      *wait_for_cb = true;
    }
  } else {
    printf("Invalid command %s\n", cmd.c_str());
    *wait_for_cb = false;
  }
}

void Commands::Store50Values(const std::string &prefix) {
  bool arrived;
  std::string key, value;
  for (int i = 0; i < 50; i++) {
    arrived = false;
    key = "";
    key = cryobj_.Hash(prefix + boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false);
    value = "";
    for (int j = 0; j < 1024*10; j++)
      value += prefix + boost::lexical_cast<std::string>(i);
      node_->StoreValue(key, value, 1040*60, boost::bind(
            &Commands::Store50Callback, this, _1, prefix +
            boost::lexical_cast<std::string>(i), &arrived));
      while (!arrived)
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  result_arrived_ = true;
}

void Commands::Store50Callback(const std::string &result,
      const std::string &key, bool *arrived) {
  kad::StoreResponse msg;
  if (!msg.ParseFromString(result)) {
    printf("ERROR. Invalid response. Kademlia Store Value key %s\n",
        key.c_str());
    result_arrived_ = true;
    return;
  }
  if (msg.result() != kad::kRpcResultSuccess) {
    printf("Failed to store %f copies of values for key %s.\n",
        min_succ_stores_, key.c_str());
    printf("Some copies might have been stored\n");
  } else {
    printf("Successfully stored key %s\n", key.c_str());
  }
  *arrived = true;
}
}
