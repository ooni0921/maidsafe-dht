/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef BASE_UTILS_H_
#define BASE_UTILS_H_

#if defined (__WIN32__) || defined (__MINGW__)
// # include <windows.h>
# include <winsock2.h>
# include <iphlpapi.h>
#else                       // apple and POSIX
# include <unistd.h>
# include <netdb.h>
# include <net/if.h>        // must be before ifaddrs.h
# include <sys/ioctl.h>
// # include <net/route.h>  // not using this for the moment
# include <sys/socket.h>    //  included in apple's net/route.h
#include <sys/types.h>      //  included in apple's net/route.h
#include <ifaddrs.h>        // used for old implementation of LocalIPPort() remove when new soln impmltd.
// do we need these?
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#endif

#include <boost/cstdint.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/xtime.hpp>
#include <boost/function.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <cryptopp/hex.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>
#include <list>

namespace base {

//  remove leading and trailing slashes from path unless path is "/"
std::string TidyPath(const std::string &original_path_);

//  convert from boost::uint64_t to string
std::string itos_ull(boost::uint64_t value);
//  convert from string to boost::uint64_t
boost::uint64_t stoi_ull(std::string value);

//  convert from boost::uint32_t to string
std::string itos_ul(boost::uint32_t value);
//  convert from string to boost::uint32_t
boost::uint32_t stoi_ul(std::string value);

//  convert from boost::int32_t to string
std::string itos_l(boost::int32_t value);
//  convert from string to boost::int32_t
boost::int32_t stoi_l(std::string value);

//  convert from int to string
std::string itos(int value);
//  convert from string to int
int stoi(std::string value);

//  convert from string to wstring
std::wstring StrToWStr(const std::string &string_);
//  convert from wstring to string
std::string WStrToStr(const std::wstring &wstring_);

//  convert string to all lowercase
std::string StrToLwr(const std::string &string_);

void SanitiseSingleQuotes(std::string *str);
bool ValidateName(const std::string &str);

typedef boost::function<void(const std::string&)> callback_func_type;
// type for function used after rpc returns
typedef boost::function<void(const std::string&, const std::string &)>
    rpc_callback_func;
typedef boost::recursive_mutex::scoped_lock pd_scoped_lock;
// notify the progress (0% -100%)
typedef boost::function<void(boost::uint8_t progress)> progress_notifier;
// a tool to generate random length of string
std::string RandomString(int len);
void sleep(float secs);
bool encode_to_hex(const std::string &value, std::string &result);
bool decode_from_hex(const std::string &value, std::string &result);
// return the total seconds after 1970.1.1
boost::uint32_t get_epoch_time();
boost::uint64_t get_epoch_milliseconds();
boost::uint64_t get_epoch_nanoseconds();
// convert an IP in decimal dotted format to IPv4
std::string inet_atob(const std::string &dec_ip);
// convert an IPv4 to decimal dotted format
std::string inet_btoa(const std::string &ipv4);
// generate next transaction id
boost::uint32_t generate_next_transaction_id(boost::uint32_t id);
void inet_ntoa(boost::uint32_t addr, char *ipbuf);
boost::uint32_t inet_aton(const char * buf);
struct device_struct {
  device_struct() : ip_address(), interface_("") {}
  boost::asio::ip::address ip_address;
  std::string interface_;
};
// return a list of network interfaces in the format of "address, adapter name"
void get_net_interfaces(std::vector<struct device_struct> *alldevices);
// return the first
bool get_local_address(boost::asio::ip::address *local_address);

// Generates a 32bit signed integer
// use this one if receiving it in a variable that is int or int32_t
// or if before assinging to a signed int variable you are doing a modulo op
int32_t random_32bit_integer();

// Generates a 32bit unsigned integer
// use this one if receiving it in a variable that is unsigned int or uint32_t
uint32_t random_32bit_uinteger();

// get a random sample of N elements of a container(vector, list, set)
// usage
// random_sample(container.begin(), container.end(), result.begin(), N)
template <class ForwardIterator, class OutputIterator>
OutputIterator random_sample_n(ForwardIterator begin, ForwardIterator end,
  OutputIterator result, int N) {
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
  return  result;
}

}  // namespace base

// TODO(jose): change the namespace to base
namespace maidsafe {

enum value_types {
  SYSTEM_PACKET, BUFFER_PACKET, BUFFER_PACKET_INFO, BUFFER_PACKET_MESSAGE,
  CHUNK_REFERENCE, WATCH_LIST, DATA, PDDIR_SIGNED, PDDIR_NOTSIGNED
};

}  // namespace maidsafe

#endif  // BASE_UTILS_H_
