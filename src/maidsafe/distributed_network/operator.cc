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

#include <boost/progress.hpp>

#include <string>
#include <set>

#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/distributed_network/mysqlppwrap.h"
#include "maidsafe/kademlia/knode-api.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"

namespace net_client {

Operator::Operator(boost::shared_ptr<kad::KNode> knode,
                   const std::string &public_key,
                   const std::string &private_key)
    : knode_(knode), wrap_(new MySqlppWrap()), halt_request_(false),
      operation_index_(0), operation_map_(), values_map_(), op_map_mutex_(),
      values_map_mutex_(), timer_(new base::CallLaterTimer()),
      public_key_(public_key), private_key_(private_key),
      public_key_signature_() {
  crypto::Crypto co;
  public_key_signature_ = co.AsymSign(public_key_, "", private_key_,
                                      crypto::STRING_STRING);
  int result = wrap_->Init("kademlia_network_test", "178.79.141.45", "root",
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
  timer_->AddCallLater(10 * 60 * 1000,
                       boost::bind(&Operator::FetchKeyValuesFromDb, this));
  timer_->AddCallLater(20 * 60 * 1000,
                       boost::bind(&Operator::ChooseOperation, this));
}

void Operator::Halt() {
  timer_->CancelAll();
}

void Operator::ScheduleInitialOperations() {
  ValuesMap::iterator it = values_map_.begin();
  for (int n = 0; n < 5; ++n) {
    std::string key((*it).key);
    kad::SignedValue sv;
    sv.ParseFromString((*it).value);
    timer_->AddCallLater((1 + n) * 1000,
                         boost::bind(&Operator::StoreValue, this, key, sv));
    ++it;
  }
}

void Operator::ChooseOperation() {
  boost::uint16_t op(base::RandomUint32() % 4);
  switch (op) {
    case 0: SendStore(); break;
    case 1: SendFind(); break;
    case 2: SendUpdate(); break;
    case 3: SendDelete(); break;
  }
  timer_->AddCallLater(5 * 60 * 1000,
                       boost::bind(&Operator::ChooseOperation, this));
}

void Operator::FetchKeyValuesFromDb() {
  std::vector<std::string> keys;
  wrap_->GetKeys(&keys);
  std::set<std::string> the_keys;
  while (the_keys.size() < size_t(7) && the_keys.size() != keys.size()) {
    std::random_shuffle(keys.begin(), keys.end());
    the_keys.insert(keys[0]);
  }

  std::set<std::string>::iterator it = the_keys.begin();
  std::vector<std::string> values;
  std::vector<kad::SignedValue> signed_values;
  bool mine(false);
  int count(1), a;
  for (; it != the_keys.end(); ++it) {
    if (KeyMine(*it))
      mine = true;
    a = wrap_->GetValues(*it, &values);
    signed_values.clear();
    if (a == 0) {
      signed_values.resize(values.size());
      for (size_t n = 0; n < values.size(); ++n)
        signed_values[n].ParseFromString(values[n]);
      timer_->AddCallLater((1 + count) * 1000,
                           boost::bind(&Operator::FindValue, this, *it,
                                       signed_values, mine));
    }
  }

  timer_->AddCallLater(10 * 60 * 1000,
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
      kad::SignedValue sv;
      sv.ParseFromString((*pvmbk.first).value);
      signed_values.push_back(sv);
      ++p.first;
    }
    FindValue(kv_vector[0].key, signed_values, true);
  }
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
  knode_->StoreValue(ki_key, sv, request_signature, 24 * 60 * 60,
                     boost::bind(&Operator::StoreValueCallback, this, op, _1));
  boost::mutex::scoped_lock loch_voil(op_map_mutex_);
  operation_map_.insert(op);
}

void Operator::StoreValueCallback(const Operation &op,
                                  const std::string &ser_result) {
  kad::StoreResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result))
    if (response.result() == kad::kRpcResultSuccess)
      success = true;

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
    }
  }
  LogResult(op, kad::SignedValue(), success);
}

void Operator::FindValue(const std::string &key,
                         const std::vector<kad::SignedValue> &values,
                         bool mine) {
  kad::KadId ki_key(key);
  Operation op(key, kad::SignedValue(), kFindValue);
  knode_->FindValue(ki_key, false,
                    boost::bind(&Operator::FindValueCallback, this, op, values,
                                mine, _1));
  boost::mutex::scoped_lock loch_voil(op_map_mutex_);
  operation_map_.insert(op);
}

void Operator::FindValueCallback(const Operation &op,
                                 const std::vector<kad::SignedValue> &values,
                                 bool mine, const std::string &ser_result) {
  kad::FindResponse result_msg;
  bool success(true);
  if (!result_msg.ParseFromString(ser_result)) {
    success = false;
  } else if (result_msg.result() == kad::kRpcResultFailure) {
    success = false;
  } else if (size_t(result_msg.signed_values_size()) != values.size()) {
    success = false;
  } else {
    int count(0);
    for (int n = 0; n < result_msg.signed_values_size(); ++n) {
      if (values[n].value() != result_msg.signed_values(n).value() ||
          values[n].value_signature() !=
              result_msg.signed_values(n).value_signature())
        ++count;
    }

    if (count != 0)
      success = false;

    if (mine) {
      count = 0;
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it;
      for (int n = 0; n < result_msg.signed_values_size(); ++n) {
         it = vmbkv_index.find(
                  boost::make_tuple(
                      op.key, result_msg.signed_values(n).SerializeAsString()));
        if (it != vmbkv_index.end()) {
          KeyValue kv = *it;
          kv.status = 1;
          vmbkv_index.replace(it, kv);
        } else {
          ++count;
        }
      }
    }

    if (count != 0)
      success = false;
  }
  LogResult(op, kad::SignedValue(), success);
}

void Operator::DeleteValue(const std::string &key, const kad::SignedValue &sv) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  Operation op(key, sv, kDelete);
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
  request->set_signed_request(co.Hash(public_key_ + public_key_signature_ + key,
                                      "", crypto::STRING_STRING, true));
}

void Operator::LogResult(const Operation &original_op,
                         const kad::SignedValue &updated_signed_value,
                         const bool &result) {
  boost::mutex::scoped_lock loch_voil(op_map_mutex_);
  OperationMap::index<by_timestamp>::type::iterator it =
      operation_map_.get<by_timestamp>().find(original_op.start_time);
  if (it == operation_map_.get<by_timestamp>().end()) {
    printf("Didn't find operation.\n");
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

bool Operator::HashableKeyPair(const std::string &key,
                               const std::string &sv,
                               crypto::Crypto *co) {
  return key == co->Hash(sv, "", crypto::STRING_STRING, false);
}

}  // namespace net_client
