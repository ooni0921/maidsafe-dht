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
 * This file defines all constants used by the maidsafe-dht library.  It also  *
 * contains forward declarations and enumerations required by the library.     *
 *                                                                             *
 * NOTE: These settings and functions may be amended or deleted in future      *
 * releases until this notice is removed.                                      *
 ******************************************************************************/

#ifndef MAIDSAFE_DHT_CONFIG_H_
#define MAIDSAFE_DHT_CONFIG_H_


#if defined (__WIN32__) || defined (__MINGW__)
#include <winsock2.h>
#include <iphlpapi.h>
#else  // apple and POSIX
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>  // must be before ifaddrs.h
#include <sys/ioctl.h>
// # include <net/route.h>  // not using this for the moment
#include <sys/socket.h>  // included in apple's net/route.h
#include <sys/types.h>  // included in apple's net/route.h
#include <ifaddrs.h>  // used for old implementation of LocalIPPort() remove
                      // when new soln impmltd.
//  // do we need these?
//  #include <arpa/inet.h>
//  #include <netinet/in.h>
//  #include <errno.h>
#endif

#include <boost/asio.hpp>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/mp_math/mp_int.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <cryptopp/hex.h>
#include <stdint.h>
#include <google/protobuf/service.h>
#include <google/protobuf/message.h>

#include <algorithm>
#include <string>
#include <vector>

/*******************************************************************************
 * KADEMLIA LAYER                                                              *
 ******************************************************************************/
namespace kad {

// KADEMLIA CONSTANTS

// The size of DHT keys and node IDs in bytes.
const int kKeySizeBytes = 64;

// Kademlia constant k which defines the size of each "k-bucket" and the number
// of nodes upon which a given <key,value> is stored.
const boost::uint16_t K = 16;

// The parallel level of search iterations.
const int kAlpha = 3;

// The number of replies required in a search iteration to allow the next
// iteration to begin.
const int kBeta = 1;

// The frequency (in seconds) of the refresh routine.
const int kRefreshTime = 3600;  // 1 hour

// The frequency (in seconds) of the <key,value> republish routine.
const int kRepublishTime = 43200;  // 12 hours

// The duration (in seconds) after which a given <key,value> is deleted locally.
const int kExpireTime = kRepublishTime+3600;

// Kademlia RPC timeout duration (in milliseconds).
const int kRpcTimeout = 7000;

// RPC result constants.
const std::string kRpcResultSuccess("T");
const std::string kRpcResultFailure("F");
// TODO(Fraser#5#): 2009-05-15 - Make these bools

// Defines whether or not an existing local <key,value> database should be
// reused (true) or overwritten (false) on initialisation of the datastore.
const bool kReuseDatabase = false;

// The ratio of k successful individual kad store RPCs to yield overall success.
const double kMinSuccessfulPecentageStore = 0.75;

// The number of failed RPCs tolerated before a contact is removed from the
// k-bucket.
const boost::uint16_t kFailedRpc = 0;

// The maximum number of bootstrap contacts allowed in the .kadconfig file.
const int kMaxBootstrapContacts = 10000;

// Signature used to sign anonymous RPC requests.
const std::string kAnonymousSignedRequest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // NOLINT


// KADEMLIA ENUMERATIONS, DATA TYPE DEFINITIONS, AND FORWARD DECLARATIONS
enum KBucketExitCode { SUCCEED, FULL, FAIL };
enum node_type { CLIENT, VAULT };
enum connect_to_node { LOCAL, REMOTE, UNKNOWN };
enum remote_find_method { FIND_NODE, FIND_VALUE, BOOTSTRAP };
typedef boost::mp_math::mp_int<> BigInt;
class KNodeImpl;
class KadRpcs;
class Contact;
class ContactInfo;
}  // namespace kad



/*******************************************************************************
 * BASE LAYER - FREE FUNCTIONS FOR USE IN ALL LAYERS                           *
 ******************************************************************************/
namespace base {

// Data type definition for general callback functions.
typedef boost::function<void(const std::string&)> callback_func_type;

// Data type definition for RPC callback functions.
typedef boost::function<void(const std::string&, const std::string &)>
    rpc_callback_func;

typedef boost::recursive_mutex::scoped_lock pd_scoped_lock;
// TODO(Fraser#5#): 2009-05-16 - remove this typedef & associated .hpp #include

typedef boost::function<void(boost::uint8_t progress)> progress_notifier;

// Remove leading and trailing slashes from path unless path is "/".
std::string TidyPath(const std::string &original_path_);

// Convert from boost::uint64_t to string.
std::string itos_ull(boost::uint64_t value);

// Convert from string to boost::uint64_t.
boost::uint64_t stoi_ull(std::string value);

// Convert from boost::uint32_t to string.
std::string itos_ul(boost::uint32_t value);

// Convert from string to boost::uint32_t.
boost::uint32_t stoi_ul(std::string value);

// Convert from boost::int32_t to string.
std::string itos_l(boost::int32_t value);

// Convert from string to boost::int32_t.
boost::int32_t stoi_l(std::string value);

// Convert from int to string.
std::string itos(int value);

// Convert from string to int.
int stoi(std::string value);

// Convert from string to wstring.
std::wstring StrToWStr(const std::string &string_);

// Convert from wstring to string.
std::string WStrToStr(const std::wstring &wstring_);

// Convert string to all lowercase.
std::string StrToLwr(const std::string &string_);

// Prepare string for use in SQLite statement by amending instances of single
// quotes to two adjoining single quotes.
void SanitiseSingleQuotes(std::string *str);

// Check for disallowed characters for filenames.
bool ValidateName(const std::string &str);

// Generate a random string.
std::string RandomString(int length);

// Make thread sleep.
void sleep(float secs);
// TODO(Fraser#5#): 2009-05-16 - remove this function

// Encode a string to hex.
bool encode_to_hex(const std::string &value, std::string &result);
// TODO(Fraser#5#): 2009-05-16 - Amend &result to pass by pointer.

// Decode a string from hex.
bool decode_from_hex(const std::string &value, std::string &result);
// TODO(Fraser#5#): 2009-05-16 - Amend &result to pass by pointer.

// Return the number of seconds since 1st January 1970.
boost::uint32_t get_epoch_time();

// Return the number of milliseconds since 1st January 1970.
boost::uint64_t get_epoch_milliseconds();

// Return the number of nanoseconds since 1st January 1970.
boost::uint64_t get_epoch_nanoseconds();

// Convert an IP in decimal dotted format to IPv4
std::string inet_atob(const std::string &dec_ip);

// Convert an IPv4 to decimal dotted format
std::string inet_btoa(const std::string &ipv4);

// Generate a (transaction) id between 1 & 2147483646 inclusive.
boost::uint32_t generate_next_transaction_id(boost::uint32_t id);

// Convert an internet network address into dotted string format.
void inet_ntoa(boost::uint32_t addr, char *ipbuf);

// Convert a dotted string format internet address into Ipv4 format.
boost::uint32_t inet_aton(const char * buf);

// Return a list of network interfaces in the format of "address, adapter name".
void get_net_interfaces(std::vector<struct device_struct> *alldevices);

// Return the first local network interface found.
bool get_local_address(boost::asio::ip::address *local_address);

// Generate a 32bit signed integer
// Use this function if receiving it in a variable that is int or int32_t
// or if before assinging to a signed int variable you are doing a modulo op
int32_t random_32bit_integer();

// Generate a 32bit unsigned integer
// Use this one if receiving it in a variable that is unsigned int or uint32_t
uint32_t random_32bit_uinteger();

struct device_struct {
  device_struct() : ip_address(), interface_("") {}
  boost::asio::ip::address ip_address;
  std::string interface_;
};

// Get a random sample of N elements of a container(vector, list, set)
// Usage:
// random_sample(container.begin(), container.end(), result.begin(), N)
template <class ForwardIterator, class OutputIterator>
    OutputIterator random_sample_n(ForwardIterator begin,
                                   ForwardIterator end,
                                   OutputIterator result,
                                   int N) {
  int remaining = std::distance(begin, end);

  // To avoid clashing of Visual Studio's min macro
  #ifdef __MSVC__
    int m = min(N, remaining);
  #else
    int m = std::min(N, remaining);
  #endif
  while (m > 0) {
    if (static_cast<int>((random_32bit_uinteger() % remaining)) < m) {
      *result = *begin;
      ++result;
      --m;
    }
    --remaining;
    ++begin;
  }
  return result;
}

class CallLaterTimer;
}  // namespace base



/*******************************************************************************
 * RPC INTERFACE                                                               *
 ******************************************************************************/
namespace rpcprotocol {

// RPC CONSTANTS

// Maximum port number.
const int kMaxPort = 65535;

// Minimum port number.
const int kMinPort = 5000;

// RPC timeout duration (in milliseconds).
const int kRpcTimeout = 7000;  // 7 seconds

// RPC result constants.
const std::string kStartTransportSuccess("T");
const std::string kStartTransportFailure("F");
// TODO(Fraser#5#): 2009-05-16 - Make these bools


// RPC ENUMERATIONS, DATA TYPE DEFINITIONS, AND FORWARD DECLARATIONS
struct RpcInfo;
struct PendingReq;
class RpcMessage;
class ChannelManagerImpl;
class ControllerImpl;
class ChannelImpl;
class ChannelManager;
class Controller;
class Channel;
}  // namespace rpcprotocol



namespace transport {
class Transport;
}
#endif  // MAIDSAFE_DHT_CONFIG_H_
