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


/*******************************************************************************
 * This file defines all main constants and enums used by the library.         *
 *                                                                             *
 * NOTE: This file is unlikely to have any breaking changes applied.  However, *
 *       it should not be regarded as final until this notice is removed.      *
 ******************************************************************************/

#ifndef MAIDSAFE_MAIDSAFE_DHT_CONFIG_H_
#define MAIDSAFE_MAIDSAFE_DHT_CONFIG_H_

#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <string>


/*******************************************************************************
 * maidsafe-dht Version                                                        *
 ******************************************************************************/
#define MAIDSAFE_DHT_VERSION 20


/*******************************************************************************
 * Platform Detection                                                          *
 ******************************************************************************/
#if !defined MAIDSAFE_POSIX && !defined MAIDSAFE_WIN32 && \
    !defined MAIDSAFE_APPLE
#if defined(linux) || defined(__linux) || defined(__linux__) || \
  defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
  defined(__DragonFly__) || defined(sun) || defined(__sun) || \
  defined(__sgi) || defined(__hpux) || defined(__BEOS__) || \
  defined(__IBMCPP__) || defined(_AIX) || defined(__QNXNTO__) || \
  defined(unix) || defined(_XOPEN_SOURCE) || defined(_POSIX_SOURCE)
#define MAIDSAFE_POSIX

#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32) || \
  defined(_WIN32_WINNT) || defined(NTDDI_VERSION) || defined(_WIN32_WINDOWS)
#define MAIDSAFE_WIN32

#elif defined(macintosh) || defined(__APPLE__) || defined(__APPLE_CC__)
#define MAIDSAFE_APPLE
#endif

#endif

/*******************************************************************************
 * Kademlia Layer                                                              *
 ******************************************************************************/
namespace kad {

// Functor for general callback functions.
typedef boost::function<void(const std::string&)> VoidFunctorOneString;

enum KBucketExitCode { SUCCEED, FULL, FAIL };

// DIRECT_CONNECTED - node is directly connected to the internet, IP is an
//                    external IP or port has been manually mapped or port
//                    mapped with UPnP
// RESTRICTED - node is behind a port or address restricted NAT, has to be
//              contacted with its rendezvous server
// NONE - node is behind a symmetric NAT and can not be contacted without it
//        making the first contact and keeping the connection open
enum NatType { DIRECT_CONNECTED, RESTRICTED, NONE };

// CLIENT - does not map external ip and port, is not stored in other  nodes
//          routing table
// CLIENT_PORT_MAPPED - maps external ip and port, is not stored in other nodes
//                      routing table
// VAULT - maps external ip and port, complete functionality of a kademlia node
enum NodeType { CLIENT, CLIENT_PORT_MAPPED, VAULT };

enum ConnectionType { LOCAL, REMOTE, UNKNOWN };

// The size of DHT keys and node IDs in bytes.
const boost::uint16_t kKeySizeBytes = 64;

// Kademlia constant k which defines the size of each "k-bucket" and the number
// of nodes upon which a given <key,value> is stored.
const boost::uint16_t K = 16;

// The parallel level of search iterations.
const boost::uint16_t kAlpha = 3;

// The number of replies required in a search iteration to allow the next
// iteration to begin.
const boost::uint16_t kBeta = 1;

// The frequency (in seconds) of the refresh routine.
const boost::uint32_t kRefreshTime = 3600;  // 1 hour

// The frequency (in seconds) of the <key,value> republish routine.
const boost::uint32_t kRepublishTime = 43200;  // 12 hours

// The duration (in seconds) after which a given <key,value> is deleted locally.
const boost::uint32_t kExpireTime = kRepublishTime + kRefreshTime + 300;

// RPC result constants.
const std::string kRpcResultSuccess("T");
const std::string kRpcResultFailure("F");
// TODO(Fraser#5#): 2009-05-15 - Make these bools

// The ratio of k successful individual kad store RPCs to yield overall success.
const double kMinSuccessfulPecentageStore = 0.75;

// The number of failed RPCs tolerated before a contact is removed from the
// k-bucket.
const boost::uint16_t kFailedRpc = 0;

// The maximum number of bootstrap contacts allowed in the .kadconfig file.
const boost::uint32_t kMaxBootstrapContacts = 10000;

// Signature used to sign anonymous RPC requests.
const std::string kAnonymousSignedRequest(2 * kKeySizeBytes, 'f');

}  // namespace kad


/*******************************************************************************
 * RPC Layer                                                                   *
 ******************************************************************************/
namespace rpcprotocol {

// Maximum port number.
const boost::uint16_t kMaxPort = 65535;

// Minimum port number.
const boost::uint16_t kMinPort = 5000;

// RPC timeout duration (in milliseconds).
const boost::uint32_t kRpcTimeout = 10000;

// RPC result constants.
const std::string kStartTransportSuccess("T");
const std::string kStartTransportFailure("F");
// TODO(Fraser#5#): 2009-05-16 - Make these bools

// RPC Error Messages
const std::string kTimeOut("T");
const std::string kCancelled("C");

}  // namespace rpcprotocol

#endif  // MAIDSAFE_MAIDSAFE_DHT_CONFIG_H_
