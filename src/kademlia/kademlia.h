/*
Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*licit written permission of the board of directors of maidsafe.net
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

