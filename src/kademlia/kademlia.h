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
 *  Created on: Oct 2, 2008
 *      Author: haiyang
 */

#ifndef KADEMLIA_KADEMLIA_H_
#define KADEMLIA_KADEMLIA_H_

#include <boost/cstdint.hpp>
#include <string>
#include "base/config.h"
#include "kademlia/kadutils.h"
#include "config.h"

namespace kad {

// kademlia paper constants
const int kKeySizeBytes = 64;
const boost::uint16_t K = 20;
const int kAlpha = 3;
const int kBeta = 1;
const int kRefreshTime = 3600;
const int kReplicateTime = 3600;  // 1 hour
const int kRepublishTime = 43200;  // 12 hours
const int kExpireTime = kRepublishTime+3600;
// RPC timeout
const int kRpcTimeout = 7000;  // 7 seconds or 5 seconds?
const int kIterativeLookupDelay = 2500;  //  1/2 kRpcTimeout
// RPC result constants
const std::string kRpcResultSuccess("T");
const std::string kRpcResultFailure("F");
const bool kReuseDatabase = false;

// constants for vault node
// the parallel level to execute vault updating
const int kUpdateVaultParallelLave = 3;
// we say it a successful operation if a certain of chunks are updated
// successfully
const float kMinSuccessfulPecentageOfUpdating = 0.9;
// number of rpc's tolerated before a contact is removed from the kbucket
const boost::uint16_t kFailedRpc = 0;
// maximum number of contacts allowed in .kadconfig file
const int kMaxBootstrapContacts = 10000;
// maximum message size which can be sent to the kademlia
// In theory, the maximum size that supported by the transport layer is 64MB
enum KBucketExitCode {
  SUCCEED, FULL, FAIL
};

typedef boost::mp_math::mp_int<> BigInt;
enum node_type {CLIENT, VAULT};
}  // namespace kademlia
#endif  // KADEMLIA_KADEMLIA_H_

