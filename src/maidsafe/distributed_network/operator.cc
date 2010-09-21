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
#include "maidsafe/base/crypto.h"
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
    std::string random_value(base::RandomString(base::RandomUint32()%20000));
    while (values.find(random_value) != values.end())
      random_value = base::RandomString(base::RandomUint32()%20000);

    values.insert(random_value);
    kad::SignedValue sv;
    sv.set_value(random_value);
    crypto::Crypto co;
    sv.set_value_signature(co.AsymSign(random_value, "", private_key_,
                                       crypto::STRING_STRING));
    std::string key(co.Hash(random_value, "", crypto::STRING_STRING, false));
    values_map_.insert(ValuesMapPair(key, ValueStatus(sv, -1)));
  }

  // Generate non-hashable values
  values.clear();
  size_t limit(split);
  while (values.size() < limit) {
    boost::uint32_t values_for_key(base::RandomUint32()%10);
    while (size_t(values_for_key) + values.size() > limit)
      values_for_key = base::RandomUint32()%10;
    std::string key(base::RandomString(64));
    for (boost::uint32_t t = 0; t < values_for_key; ++t) {
      std::string random_value(base::RandomString(base::RandomUint32()%20000));
      while (values.find(random_value) != values.end())
        random_value = base::RandomString(base::RandomUint32()%20000);

      values.insert(random_value);
      kad::SignedValue sv;
      sv.set_value(random_value);
      crypto::Crypto co;
      sv.set_value_signature(co.AsymSign(random_value, "", private_key_,
                                         crypto::STRING_STRING));
      values_map_.insert(ValuesMapPair(key, ValueStatus(sv, 0)));
    }
  }
}

void Operator::Run() {
  ScheduleInitialOperations();
}

void Operator::Halt() {
}

void Operator::ScheduleInitialOperations() {
  ValuesMap::iterator it = values_map_.begin();
  for (int n = 0; n < 5; ++n) {
    std::string key((*it).first);
    ValueStatus vst((*it).second);
    kad::SignedValue sv(vst.first);
    timer_->AddCallLater((1 + n) * 1000,
                         boost::bind(&Operator::StoreValue, this, key, sv));
    ++it;
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
      std::pair<ValuesMap::iterator, ValuesMap::iterator> p =
          values_map_.equal_range(op.key);
      bool not_found(true);
      while (p.first != p.second && not_found) {
        if ((*p.first).second.first.SerializeAsString() ==
            op.signed_value.SerializeAsString()) {
          not_found = false;
          (*p.first).second.second = -2;
        } else {
          ++p.first;
        }
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
                    boost::bind(&Operator::FindValueCallback, this,
                                key, values, mine, op.start_time, _1));
}

void Operator::FindValueCallback(const std::string &key,
                                 const std::vector<kad::SignedValue> &values,
                                 bool mine,
                                 boost::posix_time::ptime &start_time,
                                 const std::string &ser_result) {
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(ser_result))
    return;

  if (result_msg.result() == kad::kRpcResultFailure)
    return;

  if (size_t(result_msg.signed_values_size()) != values.size())
    return;

  int count(0);
  for (int n = 0; n < result_msg.signed_values_size(); ++n) {
    if (values[n].value() != result_msg.signed_values(n).value() ||
        values[n].value_signature() !=
            result_msg.signed_values(n).value_signature())
      ++count;
  }

  if (mine) {
    boost::mutex::scoped_lock loch_voil(values_map_mutex_);
    std::pair<ValuesMap::iterator, ValuesMap::iterator> p =
        values_map_.equal_range(key);
    while (p.first != p.second) {
      ++(*p.first).second.second;
      ++p.first;
    }
  }
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
      std::pair<ValuesMap::iterator, ValuesMap::iterator> p =
          values_map_.equal_range(op.key);
      bool not_found(true);
      while (p.first != p.second && not_found) {
        if ((*p.first).second.first.SerializeAsString() ==
            op.signed_value.SerializeAsString()) {
          not_found = false;
          (*p.first).second.second = -2;
        } else {
          ++p.first;
        }
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
      std::pair<ValuesMap::iterator, ValuesMap::iterator> p =
          values_map_.equal_range(op.key);
      bool not_found(true);
      while (p.first != p.second && not_found) {
        if ((*p.first).second.first.SerializeAsString() == ser_old_value) {
          not_found = false;
          (*p.first).second.second = 0;
        } else {
          ++p.first;
        }
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

void Operator::FindKClosestNodesCallback(const std::string &key,
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
                         const kad::SignedValue updated_signed_value,
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
}  // namespace net_client
