/* Copyright (c) 2010 maidsafe.net limited
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

#include "maidsafe/distributed_network/operator.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/progress.hpp>
#include <boost/filesystem/fstream.hpp>

#include <string>
#include <set>

#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/distributed_network/mysqlppwrap.h"
#include "maidsafe/kademlia/knode-api.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace net_client {

Operator::Operator(boost::shared_ptr<kad::KNode> knode,
                   const std::string &public_key,
                   const std::string &private_key)
    : knode_(knode), wrap_(new MySqlppWrap()), halt_request_(false),
      operation_index_(0), fetch_count_(0), random_operations_(0),
      operation_map_(), values_map_(), op_map_mutex_(), values_map_mutex_(),
      timer_(new base::CallLaterTimer()), public_key_(public_key),
      private_key_(private_key), public_key_signature_() {
  try {
    fs::remove(fs::path("/tmp/ResultLog.txt"));
  }
  catch(...) {}
  crypto::Crypto co;
  public_key_signature_ = co.AsymSign(public_key_, "", private_key_,
                                      crypto::STRING_STRING);
  int result = wrap_->Init("kademlia_network_test", "127.0.0.1", "root",
                           "m41ds4f3", "kademliavalues");
  printf("Operator::Operator - DB init result: %d\n", result);
  {
    boost::progress_timer t;
    GenerateValues(2000);
  }

  printf("Operator::Operator - Done generating 2000 values\n");
}

void Operator::GenerateValues(int size) {
  if (size%2 != 0)
    ++size;

  int split(size/2);

  // Generate hashable values
  std::set<std::string> values;
  for (int n = 0; n < split; ++n) {
    boost::uint16_t t(base::RandomUint32() % 1000);
    std::string random_value(base::RandomString(20000 + t));
    while (values.find(random_value) != values.end())
      random_value = base::RandomString(20000 + t);

    values.insert(random_value);
    kad::SignedValue sv;
    sv.set_value(random_value);
    crypto::Crypto co;
    sv.set_value_signature(co.AsymSign(random_value, "", private_key_,
                                       crypto::STRING_STRING));
    std::string key(co.Hash(random_value, "", crypto::STRING_STRING, false));
    values_map_.insert(KeyValue(key, sv.SerializeAsString(), -1));
  }

  // Generate non-hashable values
  values.clear();
  size_t limit(split);
  while (values.size() < limit) {
    boost::uint16_t values_for_key(base::RandomUint32() % 10);
    while (size_t(values_for_key) + values.size() > limit)
      values_for_key = base::RandomUint32() % 10;
    std::string key(base::RandomString(64));
    for (boost::uint32_t t = 0; t < values_for_key; ++t) {
      boost::uint16_t t(base::RandomUint32() % 1000);
      std::string random_value(base::RandomString(20000 + t));
      while (values.find(random_value) != values.end())
        random_value = base::RandomString(20000 + t);

      values.insert(random_value);
      kad::SignedValue sv;
      sv.set_value(random_value);
      crypto::Crypto co;
      sv.set_value_signature(co.AsymSign(random_value, "", private_key_,
                                         crypto::STRING_STRING));
      values_map_.insert(KeyValue(key, sv.SerializeAsString(), -1));
    }
  }
}

void Operator::Run() {
  ScheduleInitialOperations();
//  timer_->AddCallLater(2 * 60 * 1000,
//                       boost::bind(&Operator::FetchKeyValuesFromDb, this));
//  timer_->AddCallLater(2 * 60 * 1000,
//                       boost::bind(&Operator::ChooseOperation, this));
}

void Operator::Halt() {
  timer_->CancelAll();
  wrap_->Delete("", "");
}

void Operator::WriteResultLog() {
  boost::mutex::scoped_lock loch_voil(op_map_mutex_);
  fs::ofstream ofs(fs::path("/tmp/ResultLog.txt"), std::ios_base::app);
  OperationMapByTimestamp &ombt_index = operation_map_.get<by_timestamp>();
  OperationMapByTimestamp::iterator it = ombt_index.begin();
  std::string s;
  while (it != ombt_index.end()) {
    Operation o = *it;
    std::string time(to_simple_string(o.start_time));
    std::string duration(boost::lexical_cast<std::string>(
                             o.duration.total_microseconds() / 1000000));
    std::string key(base::EncodeToHex(o.key));
    std::string value(base::EncodeToHex(o.signed_value.SerializeAsString()));
    std::string new_value(base::EncodeToHex(
                              o.updated_signed_value.SerializeAsString()));
    std::string result;
    if (o.result)
      result = std::string("Success");
    else
      result = std::string("Failure");

    s = time + " - Duration: " + duration + " secs - Result: " + result;
    switch (o.op_type) {
      case kStore: s += std::string(" - Store - key(") + key +
                        std::string("), value(") + value.substr(0, 24) +
                        std::string(")");
                   break;
      case kFindValue: s += std::string(" - Find - key(") + key +
                            std::string(")");
                       break;
      case kDelete: s += std::string(" - Delete - key(") + key +
                         std::string("), value(") + value.substr(0, 24) +
                         std::string(")");
                   break;
          break;
      case kUpdate: s += std::string(" - Update - key(") + key +
                         std::string(") from value(") + value.substr(0, 24) +
                         std::string(") to value (") + new_value.substr(0, 24) +
                         std::string(")");
          break;
      case kFindNodes: break;
    }
    ofs << s << std::endl;
    ++it;
  }
  ofs.close();
}

void Operator::ScheduleInitialOperations() {
  for (int n = 0; n < 50; ++n) {
    if (timer_->AddCallLater((1 + n) * 1000,
                             boost::bind(&Operator::SendStore, this)) ==
        std::numeric_limits<boost::uint32_t>::max())
      printf("Failure in Operator::ScheduleInitialOperations %d\n", n);
  }

  timer_->AddCallLater(10 * 1000,
                       boost::bind(&Operator::FetchKeyValuesFromDb, this));
//  timer_->AddCallLater(10 * 1000,
//                       boost::bind(&Operator::ChooseOperation, this));
}

void Operator::ChooseOperation() {
  ++random_operations_;
  boost::uint16_t op(base::RandomUint32() % 4);
  switch (op) {
    case 0: SendStore(); break;
    case 1: SendFind(); break;
    case 2: SendUpdate(); break;
    case 3: SendDelete(); break;
  }
  if (random_operations_ < 10)
    timer_->AddCallLater(60 * 1000,
                         boost::bind(&Operator::ChooseOperation, this));
}

void Operator::FetchKeyValuesFromDb() {
  ++fetch_count_;
  std::vector<std::string> keys;
  wrap_->GetKeys(&keys);
  std::set<std::string> the_keys;
  std::random_shuffle(keys.begin(), keys.end());

  bool mine(false);
  if (KeyMine(keys[0]))
    mine = true;

  std::vector<std::string> values;
  int a = wrap_->GetValues(keys[0], &values);

  if (a == 0) {
    std::vector<kad::SignedValue> signed_values;
    signed_values.resize(values.size());
    for (size_t n = 0; n < values.size(); ++n)
      signed_values[n].ParseFromString(values[n]);
    FindValue(keys[0], signed_values, mine);
  }

  if (fetch_count_ < 25)
    timer_->AddCallLater(20 * 1000,
                         boost::bind(&Operator::FetchKeyValuesFromDb, this));
}

void Operator::SendStore() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(-1);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    kad::SignedValue sv;
    sv.ParseFromString(kv_vector[0].value);
    StoreValue(kv_vector[0].key, sv);
  }
}

void Operator::SendFind() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(0);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    ValuesMapByKey &vmbk_index = values_map_.get<by_valuemap_key>();
    std::pair<ValuesMapByKey::iterator, ValuesMapByKey::iterator> pvmbk =
        vmbk_index.equal_range(kv_vector[0].key);

    std::vector<kad::SignedValue> signed_values;
    while (pvmbk.first != pvmbk.second) {
      if ((*pvmbk.first).status == 0) {
        kad::SignedValue sv;
        sv.ParseFromString((*pvmbk.first).value);
        signed_values.push_back(sv);
      }
      ++pvmbk.first;
    }
    FindValue(kv_vector[0].key, signed_values, true);
  }
  timer_->AddCallLater(10 * 1000,
                       boost::bind(&Operator::SendFind, this));
}

void Operator::SendUpdate() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(0);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    crypto::Crypto co;
    size_t count(0);
    while (HashableKeyPair(kv_vector[count].key, kv_vector[count].value, &co))
      ++count;
    kad::SignedValue sv;
    sv.ParseFromString(kv_vector[count].value);
    kad::SignedValue new_value;
    new_value.set_value(base::RandomString(base::RandomUint32()%500 + 20000));
    new_value.set_value_signature(co.AsymSign(new_value.value(), "",
                                              private_key_,
                                              crypto::STRING_STRING));
    UpdateValue(kv_vector[count].key, sv, new_value);
  }
}

void Operator::SendDelete() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(0);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    kad::SignedValue sv;
    sv.ParseFromString(kv_vector[0].value);
    DeleteValue(kv_vector[0].key, sv);
  }
}

void Operator::StoreValue(const std::string &key, const kad::SignedValue &sv) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  Operation op(key, sv, kStore);
  {
    boost::mutex::scoped_lock loch_voil(op_map_mutex_);
    std::pair<OperationMap::iterator, bool> p = operation_map_.insert(op);
    if (!p.second)
      printf("\n\nTHIS IS  WHY ONE SHOULD CHECK FOR INSERTION!!!!\n\n");
    else
      printf("Operator::StoreValue - %s\n",
             to_simple_string(op.start_time).c_str());
  }
  knode_->StoreValue(ki_key, sv, request_signature, 24 * 60 * 60,
                     boost::bind(&Operator::StoreValueCallback, this, op, _1));
}

void Operator::StoreValueCallback(const Operation &op,
                                  const std::string &ser_result) {
  kad::StoreResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result)) {
    if (response.result() == kad::kRpcResultSuccess) {
      success = true;
    } else {
      printf("\n\nStore Failure\n\n");
    }
  } else {
    printf("\n\nStore Parse Failure\n\n");
  }

  if (success) {
    int n = wrap_->Insert(op.key, op.signed_value.SerializeAsString());
    if (n == 0) {
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it =
          vmbkv_index.find(
              boost::make_tuple(op.key, op.signed_value.SerializeAsString()));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.status = 0;
        vmbkv_index.replace(it, kv);
      } else {
        success = false;
      }
    } else {
      printf("\n\nWELL, JUST GO SIT ON A SPIKE, THEN\n\n");
    }
  } else {
  }
  LogResult(op, kad::SignedValue(), success);
}

void Operator::FindValue(const std::string &key,
                         const std::vector<kad::SignedValue> &values,
                         bool mine) {
  kad::KadId ki_key(key);
  Operation op(key, kad::SignedValue(), kFindValue);
  {
    boost::mutex::scoped_lock loch_voil(op_map_mutex_);
    std::pair<OperationMap::iterator, bool> p = operation_map_.insert(op);
    if (!p.second)
      printf("\n\nTHIS IS  WHY ONE SHOULD CHECK FOR INSERTION!!!!\n\n");
    else
      printf("Operator::FindValue - %s\n",
             to_simple_string(op.start_time).c_str());
  }
  knode_->FindValue(ki_key, false,
                    boost::bind(&Operator::FindValueCallback, this, op, values,
                                mine, _1));
}

void Operator::FindValueCallback(const Operation &op,
                                 const std::vector<kad::SignedValue> &values,
                                 bool mine, const std::string &ser_result) {
  kad::FindResponse result_msg;
  bool success(true);
  if (!result_msg.ParseFromString(ser_result)) {
    printf("\n\nAAAAA\n");
    success = false;
  } else if (result_msg.result() == kad::kRpcResultFailure) {
    printf("\n\nBBBBB\n");
    success = false;
  } else if (size_t(result_msg.signed_values_size()) != values.size()) {
    printf("\n\nCCCC\n");
    success = false;
  } else {
    std::set<std::string> a, b, c, d;
    for (size_t y = 0; y < values.size(); ++y) {
      a.insert(values[y].value());
      b.insert(values[y].value_signature());
    }

    for (int n = 0; n < result_msg.signed_values_size(); ++n) {
      c.insert(result_msg.signed_values(n).value());
      d.insert(result_msg.signed_values(n).value_signature());
    }

    if (a != c || b != d) {
      printf("\n\nDDDD\n");
      success = false;
    } else if (mine) {
      int count = 0;
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it;
      for (int n = 0; n < result_msg.signed_values_size(); ++n) {
         it = vmbkv_index.find(
                  boost::make_tuple(
                      op.key, result_msg.signed_values(n).SerializeAsString()));
        if (it != vmbkv_index.end()) {
          KeyValue kv = *it;
          ++kv.searches;
          vmbkv_index.replace(it, kv);
        } else {
          ++count;
        }
      }

      if (count != 0) {
        success = false;
        printf("\n\nEEEE\n");
      }
    }
  }
  printf("\nFindValueCallback DONE - %d\n\n", success);
  LogResult(op, kad::SignedValue(), success);
}

void Operator::DeleteValue(const std::string &key, const kad::SignedValue &sv) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  Operation op(key, sv, kDelete);
  {
    boost::mutex::scoped_lock loch_voil(op_map_mutex_);
    std::pair<OperationMap::iterator, bool> p = operation_map_.insert(op);
    if (!p.second)
      printf("\n\nTHIS IS  WHY ONE SHOULD CHECK FOR INSERTION!!!!\n\n");
    else
      printf("Operator::DeleteValue - %s\n",
             to_simple_string(op.start_time).c_str());
  }
  knode_->DeleteValue(ki_key, sv, request_signature,
                      boost::bind(&Operator::DeleteValueCallback, this, op,
                                  _1));
}

void Operator::DeleteValueCallback(const Operation &op,
                                   const std::string &ser_result) {
  kad::DeleteResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result))
    if (response.result() == kad::kRpcResultSuccess)
      success = true;

  if (success) {
    int n = wrap_->Delete(op.key, op.signed_value.SerializeAsString());
    if (n == 0) {
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it =
          vmbkv_index.find(
              boost::make_tuple(op.key, op.signed_value.SerializeAsString()));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.status = -1;
        vmbkv_index.replace(it, kv);
      } else {
        success = false;
      }
    }
  }
  LogResult(op, kad::SignedValue(), success);
}

void Operator::UpdateValue(const std::string &key,
                           const kad::SignedValue &old_value,
                           const kad::SignedValue &new_value) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  Operation op(key, old_value, kUpdate);
  {
    boost::mutex::scoped_lock loch_voil(op_map_mutex_);
    std::pair<OperationMap::iterator, bool> p = operation_map_.insert(op);
    if (!p.second)
      printf("\n\nTHIS IS  WHY ONE SHOULD CHECK FOR INSERTION!!!!\n\n");
    else
      printf("Operator::UpdateValue - %s\n",
             to_simple_string(op.start_time).c_str());
  }
  knode_->UpdateValue(ki_key, old_value, new_value, request_signature,
                      24 * 60 * 60, boost::bind(&Operator::UpdateValueCallback,
                                                this, op, new_value, _1));
}

void Operator::UpdateValueCallback(const Operation &op,
                                   const kad::SignedValue &new_value,
                                   const std::string &ser_result) {
  kad::UpdateResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result))
    if (response.result() == kad::kRpcResultSuccess)
      success = true;

  std::string ser_old_value(op.signed_value.SerializeAsString());
  if (success) {
    int n = wrap_->Update(op.key, ser_old_value, new_value.SerializeAsString());
    if (n == 0) {
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it =
          vmbkv_index.find(
              boost::make_tuple(op.key, op.signed_value.SerializeAsString()));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.status = 0;
        vmbkv_index.replace(it, kv);
      } else {
        success = false;
      }
    }
  }
  LogResult(op, new_value, success);
}

void Operator::FindKClosestNodes(const std::string &key) {
  kad::KadId ki_key(key);
  knode_->FindKClosestNodes(ki_key,
      boost::bind(&Operator::FindKClosestNodesCallback, this, key, _1));
}

void Operator::FindKClosestNodesCallback(const std::string&,
                                         const std::string &ser_result) {
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(ser_result))
    return;

  if (result_msg.result() == kad::kRpcResultFailure)
    return;

  if (result_msg.closest_nodes_size() == 0)
    return;

  for (int n = 0; n < result_msg.closest_nodes_size(); ++n) {
  }
}

void Operator::CreateRequestSignature(const std::string &key,
                                      kad::SignedRequest *request) {
  request->set_signer_id(knode_->node_id().String());
  request->set_public_key(public_key_);
  request->set_signed_public_key(public_key_signature_);
  crypto::Crypto co;
  std::string request_hash(co.Hash(public_key_ + public_key_signature_ + key,
                                   "", crypto::STRING_STRING, false));
  request->set_signed_request(co.AsymSign(request_hash, "", private_key_,
                                          crypto::STRING_STRING));
}

void Operator::LogResult(const Operation &original_op,
                         const kad::SignedValue &updated_signed_value,
                         const bool &result) {
  printf("Operator::LogResult %s.\n\n",
         to_simple_string(original_op.start_time).c_str());
  boost::mutex::scoped_lock loch_voil(op_map_mutex_);
  OperationMap::index<by_timestamp>::type::iterator it =
      operation_map_.get<by_timestamp>().find(original_op.start_time);
  if (it == operation_map_.get<by_timestamp>().end()) {
    printf("Didn't find operation %s.\n\n",
           to_simple_string(original_op.start_time).c_str());
    return;
  }
  Operation op = *it;
  op.duration = boost::posix_time::microseconds(
                    (boost::posix_time::microsec_clock::universal_time() -
                     original_op.start_time).total_microseconds());
  op.result = result;
  op.updated_signed_value = updated_signed_value;
  operation_map_.get<by_timestamp>().replace(it, op);
}

bool Operator::KeyMine(const std::string &key) {
  ValuesMapByKey &vmbk_index = values_map_.get<by_valuemap_key>();
  ValuesMapByKey::iterator it = vmbk_index.find(key);
  return it == vmbk_index.end() ? false : true;
}

bool Operator::HashableKeyPair(const std::string &key, const std::string &sv,
                               crypto::Crypto *co) {
  return key == co->Hash(sv, "", crypto::STRING_STRING, false);
}

}  // namespace net_client
