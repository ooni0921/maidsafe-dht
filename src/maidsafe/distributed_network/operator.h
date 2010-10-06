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

#ifndef MAIDSAFE_DISTRIBUTED_NETWORK_OPERATOR_H_
#define MAIDSAFE_DISTRIBUTED_NETWORK_OPERATOR_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "maidsafe/base/crypto.h"
#include "maidsafe/protobuf/signed_kadvalue.pb.h"

namespace mi = boost::multi_index;

namespace base {
class CallLaterTimer;
}  // namespace base

namespace kad {
class KNode;
class SignedValue;
class SignedRequest;
}  // namespace kad

namespace net_client {

class MySqlppWrap;

enum OpType { kStore, kFindValue, kDelete, kUpdate, kFindNodes };

struct Operation {
  Operation()
      : key(), signed_value(), updated_signed_value(),
        start_time(boost::posix_time::microsec_clock::universal_time()),
        duration(0), op_type(kStore), result(false) {}
  Operation(const std::string &key, const kad::SignedValue &signed_value,
            const OpType &op_type)
      : key(key), signed_value(signed_value), updated_signed_value(),
        start_time(boost::posix_time::microsec_clock::universal_time()),
        duration(0), op_type(op_type), result(false) {}
  std::string key;
  kad::SignedValue signed_value, updated_signed_value;
  boost::posix_time::ptime start_time;
  boost::posix_time::microseconds duration;
  OpType op_type;
  bool result;
};

// Tags
struct by_operation_key {};
struct by_timestamp {};
struct by_duration {};
struct by_operation {};

typedef boost::multi_index_container<
  Operation,
  mi::indexed_by<
    mi::ordered_non_unique<
      mi::tag<by_operation_key>,
      BOOST_MULTI_INDEX_MEMBER(Operation, std::string, key)
    >,
    mi::ordered_unique<
      mi::tag<by_timestamp>,
      BOOST_MULTI_INDEX_MEMBER(Operation, boost::posix_time::ptime, start_time)
    >,
    mi::ordered_non_unique<
      mi::tag<by_duration>,
      BOOST_MULTI_INDEX_MEMBER(Operation, boost::posix_time::microseconds,
                               duration)
    >,
    mi::ordered_non_unique<
      mi::tag<by_operation>,
      BOOST_MULTI_INDEX_MEMBER(Operation, OpType, op_type)
    >
  >
> OperationMap;

typedef OperationMap::index<by_timestamp>::type OperationMapByTimestamp;

// Tags
struct by_valuemap_key {};
struct by_value {};
struct by_key_value {};
struct by_status {};

struct KeyValue {
  KeyValue() : key(), value(), status(-1), searches(0) {}
  KeyValue(const std::string &skey, const std::string &svalue, int istatus)
      : key(skey), value(svalue), status(istatus), searches(0) {}
  std::string key, value;
  int status, searches;
};

typedef boost::multi_index_container<
  KeyValue,
  mi::indexed_by<
    mi::ordered_non_unique<
      mi::tag<by_valuemap_key>,
      BOOST_MULTI_INDEX_MEMBER(KeyValue, std::string, key)
    >,
    mi::ordered_unique<
      mi::tag<by_value>,
      BOOST_MULTI_INDEX_MEMBER(KeyValue, std::string, value)
    >,
    mi::ordered_unique<
      mi::tag<by_key_value>,
      mi::composite_key<
        KeyValue,
        BOOST_MULTI_INDEX_MEMBER(KeyValue, std::string, key),
        BOOST_MULTI_INDEX_MEMBER(KeyValue, std::string, value)
      >
    >,
    mi::ordered_non_unique<
      mi::tag<by_status>,
      BOOST_MULTI_INDEX_MEMBER(KeyValue, int, status)
    >
  >
> ValuesMap;

typedef ValuesMap::index<by_key_value>::type ValuesMapByKeyValue;
typedef ValuesMap::index<by_valuemap_key>::type ValuesMapByKey;
typedef ValuesMap::index<by_status>::type ValuesMapByStatus;

class Operator {
 public:
  Operator(boost::shared_ptr<kad::KNode> knode, const std::string &public_key,
           const std::string &private_key);
  void Run();
  void Halt();
  void WriteResultLog();

 private:
  Operator(const Operator&);
  Operator &operator=(const Operator&);

  //
  void GenerateValues(int size);
  void ScheduleInitialOperations();
  void ChooseOperation();
  void FetchKeyValuesFromDb();
  void SendStore();
  void SendFind();
  void SendUpdate();
  void SendDelete();

  // Operations
  void StoreValue(const std::string &key, const kad::SignedValue &sv);
  void FindValue(const std::string &key,
                 const std::vector<kad::SignedValue> &values,
                 bool mine);
  void DeleteValue(const std::string &key, const kad::SignedValue &sv);
  void UpdateValue(const std::string &key,
                   const kad::SignedValue &old_value,
                   const kad::SignedValue &new_value);
  void FindKClosestNodes(const std::string &key);

  // Operation Callbacks
  void StoreValueCallback(const Operation &op, const std::string &ser_result);
  void FindValueCallback(const Operation &op,
                         const std::vector<kad::SignedValue> &values,
                         bool mine, const std::string &ser_result);
  void DeleteValueCallback(const Operation &op, const std::string &ser_result);
  void UpdateValueCallback(const Operation &op,
                           const kad::SignedValue &new_value,
                           const std::string &ser_result);
  void FindKClosestNodesCallback(const std::string &key,
                                 const std::string &ser_result);

  // Miscellaneous
  void CreateRequestSignature(const std::string &key,
                              kad::SignedRequest *request);
  void LogResult(const Operation &original_op,
                 const kad::SignedValue &updated_signed_value,
                 const bool &result);
  bool KeyMine(const std::string &key);
  bool HashableKeyPair(const std::string &key, const std::string &sv,
                       crypto::Crypto *co);

  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<MySqlppWrap> wrap_;
  volatile bool halt_request_;
  int operation_index_, fetch_count_, random_operations_;
  OperationMap operation_map_;
  ValuesMap values_map_;
  boost::mutex op_map_mutex_, values_map_mutex_;
  boost::shared_ptr<base::CallLaterTimer> timer_;
  std::string public_key_, private_key_, public_key_signature_;
};

}  // namespace net_client

#endif  // MAIDSAFE_DISTRIBUTED_NETWORK_OPERATOR_H_
