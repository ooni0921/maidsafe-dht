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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <ctype.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <string>
#include <limits>
#include "base/config.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/utils.h"

namespace base {

std::string TidyPath(const std::string &original_path_) {
  //  if path is root, don't change it
  if (original_path_.size() == 1)
    return original_path_;
  std::string amended_path_ = original_path_;
  //  if path has training slash, remove it
  if (amended_path_.at(amended_path_.size()-1) == '/'\
    || amended_path_.at(amended_path_.size()-1) == '\\')
    amended_path_ = amended_path_.substr(0, amended_path_.size()-1);
  //  if path has leading slash, remove it
  if (amended_path_.at(0) == '/' || amended_path_.at(0) == '\\')
    amended_path_ = amended_path_.substr(1, amended_path_.size()-1);
  return amended_path_;
}

std::string itos_ull(boost::uint64_t value) {
  std::stringstream out;
  out << value;
  return out.str();
}

boost::uint64_t stoi_ull(std::string value) {
  boost::uint64_t result;
  std::istringstream i(value);
  i >> result;
  return result;
}

std::string itos_ul(boost::uint32_t value) {
  std::stringstream out;
  out << value;
  return out.str();
}

boost::uint32_t stoi_ul(std::string value) {
  boost::uint32_t result;
  std::istringstream i(value);
  i >> result;
  return result;
}

std::string itos_l(boost::int32_t value) {
  std::stringstream out;
  out << value;
  return out.str();
}

boost::int32_t stoi_l(std::string value) {
  boost::int32_t result;
  std::istringstream i(value);
  i >> result;
  return result;
}

std::string itos(int value) {
  std::ostringstream out;
  out << value;
  return out.str();
}

int stoi(std::string value) {
  int result;
  std::istringstream i(value);
  i >> result;
  return result;
}

std::wstring StrToWStr(const std::string &string_) {
  std::wstring wstring_(string_.length(), L' ');
  std::copy(string_.begin(), string_.end(), wstring_.begin());
  return wstring_;
}

std::string WStrToStr(const std::wstring &wstring_) {
  std::string string_(wstring_.length(), ' ');
  std::copy(wstring_.begin(), wstring_.end(), string_.begin());
  return string_;
}

std::string StrToLwr(const std::string &string_) {
  std::string lowercase_ = "";
  for (unsigned int i = 0; i < string_.length(); i++) {
    lowercase_ += tolower(string_.at(i));
  }
  return lowercase_;
}

bool ValidateName(const std::string &str) {
  for (unsigned int i = 0; i < str.length(); i++) {
    switch (str[i]) {
      case '\\':return false;
      case '/':return false;
      case ':':return false;
      case '*':return false;
      case '?':return false;
      case '"':return false;
      case '<':return false;
      case '>':return false;
      case '|':return false;
    }
  }
  return true;
}

std::string RandomString(int length) {
  std::string str;
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::Integer rand_num(rng, 32);
  for ( int i = 0 ; i < length ; ++i ) {
    boost::uint32_t num;
    if (!rand_num.IsConvertableToLong()) {
      num = std::numeric_limits<uint32_t>::max() + static_cast<uint32_t>(\
        rand_num.AbsoluteValue().ConvertToLong());
    } else {
      num = static_cast<uint32_t>(rand_num.AbsoluteValue().ConvertToLong());
    }
    num = num % 122;
    if ( 48 > num )
      num += 48;
    if ( ( 57 < num ) && ( 65 > num ) )
      num += 7;
    if ( ( 90 < num ) && ( 97 > num ) )
      num += 6;
    str += static_cast<char>(num);
    rand_num.Randomize(rng, 32);
  }
  return str;
}

bool encode_to_hex(const std::string &non_hex_in, std::string *hex_out) {
  CryptoPP::StringSource(non_hex_in, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(*hex_out), false));
  return (hex_out->size() == non_hex_in.size()*2);
}

bool decode_from_hex(const std::string &hex_in, std::string *non_hex_out) {
  CryptoPP::StringSource(hex_in, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(*non_hex_out)));
  return (static_cast<int>(non_hex_out->size() * 2) ==
      static_cast<int>(hex_in.size()));
}

std::string inet_atob(const std::string &dec_ip) {
  boost::asio::ip::address_v4 host_ip_v4 =
      boost::asio::ip::address_v4::from_string(dec_ip);
  boost::asio::ip::address_v4::bytes_type address_ = host_ip_v4.to_bytes();
  unsigned char c_str_address[4] = {(unsigned char)address_[0],
    (unsigned char)address_[1], (unsigned char)address_[2],
    (unsigned char)address_[3]};
  std::string result(reinterpret_cast<const char*>(c_str_address), 4);
  return result;
}

std::string inet_btoa(const std::string &ipv4) {
  boost::asio::ip::address_v4::bytes_type address_;
  for (int i = 0; i < 4; i++)
    address_[i] = (unsigned char)ipv4[i];
  boost::asio::ip::address_v4 host_ip_v4(address_);
  return host_ip_v4.to_string();
}

boost::uint32_t get_epoch_time() {
  boost::posix_time::ptime
    t(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::ptime start(boost::gregorian::date(1970, 1, 1));
  return static_cast<boost::uint32_t>((t-start).total_seconds());
}

boost::uint64_t get_epoch_milliseconds() {
  boost::posix_time::ptime
    t(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::ptime start(boost::gregorian::date(1970, 1, 1));
  return static_cast<boost::uint64_t>((t-start).total_milliseconds());
}

boost::uint64_t get_epoch_nanoseconds() {
  boost::posix_time::ptime
    t(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::ptime start(boost::gregorian::date(1970, 1, 1));
  return static_cast<boost::uint64_t>((t-start).total_nanoseconds());
}

boost::uint32_t generate_next_transaction_id(const boost::uint32_t &id) {
  boost::uint32_t next_id;
  boost::uint32_t max_id = 2147483646;
  if (id == 0) {
    next_id = (random_32bit_integer()+get_epoch_time()%10000)%max_id;
    if (next_id == 0)
      next_id = 1;
  } else {
    next_id = (id+1)%max_id;
    if (next_id == 0)
      next_id = 1;
  }
  return next_id;
}

void inet_ntoa(boost::uint32_t addr, char * ipbuf) {
  // TODO(dan): warning thrown on 64-bit machine
  const int sizer = 15;
  snprintf(ipbuf, sizer, "%u.%u.%u.%u", (addr>>24)&0xFF, \
    (addr>>16)&0xFF, (addr>>8)&0xFF, (addr>>0)&0xFF);
}

boost::uint32_t inet_aton(const char * buf) {
  // net_server inexplicably doesn't have this function; so I'll just fake it
  boost::uint32_t ret = 0;
  int shift = 24;  //  fill out the MSB first
  bool startQuad = true;
  while ((shift >= 0)&&(*buf)) {
    if (startQuad) {
      unsigned char quad = (unsigned char) atoi(buf);
      ret |= (((boost::uint32_t)quad) << shift);
      shift -= 8;
    }
    startQuad = (*buf == '.');
    buf++;
  }
  return ret;
}

// POSIX and APPLE Socket implementation
#if defined(MAIDSAFE_POSIX) || defined (MAIDSAFE_APPLE)
// || defined (__MINGW__)
static boost::uint32_t SockAddrToUint32(struct sockaddr * a) {
  return ((a)&&(a->sa_family == AF_INET)) ?
      ntohl(((struct sockaddr_in *)a)->sin_addr.s_addr) : 0;
}
#endif

void get_net_interfaces(std::vector<struct device_struct> *alldevices) {
  boost::asio::ip::address ip_address_tmp;
  device_struct singledevice;
#if defined(MAIDSAFE_POSIX) || defined (MAIDSAFE_APPLE)
  struct ifaddrs * ifap;
  if (getifaddrs(&ifap) == 0) {
    struct ifaddrs * p = ifap;
    while (p) {
      boost::uint32_t ifaAddr = SockAddrToUint32(p->ifa_addr);
      boost::uint32_t maskAddr = SockAddrToUint32(p->ifa_netmask);
      boost::uint32_t dstAddr = SockAddrToUint32(p->ifa_dstaddr);
      if (ifaAddr > 0) {
        char ifaAddrStr[32];
        base::inet_ntoa(ifaAddr, ifaAddrStr);
        char maskAddrStr[32];
        base::inet_ntoa(maskAddr, maskAddrStr);
        char dstAddrStr[32];
        base::inet_ntoa(dstAddr, dstAddrStr);
        ip_address_tmp = boost::asio::ip::address(
          boost::asio::ip::address().from_string(ifaAddrStr));
        device_struct singledevice;
        singledevice.ip_address = ip_address_tmp;
        singledevice.interface_ = p->ifa_name;
        // add the device to the vector
        alldevices->push_back(singledevice);
      }
        p = p->ifa_next;
    }
    freeifaddrs(ifap);
  }

#elif defined(MAIDSAFE_WIN32)
  //  To get Windows IPv4 address table, we have to call GetIpAddrTable()
  //  multiple times in order to deal with potential race conditions properly.
  //  See comment below.
  MIB_IPADDRTABLE * ipTable = NULL;
  // {
  ULONG bufLen = 0;
  for (int i = 0; i < 5; i++) {
    DWORD ipRet = GetIpAddrTable(ipTable, &bufLen, false);
    if (ipRet == ERROR_INSUFFICIENT_BUFFER) {
      free(ipTable);  //  in case we had previously allocated it
      ipTable = reinterpret_cast<MIB_IPADDRTABLE *>(malloc(bufLen));
    } else {
      if (ipRet == NO_ERROR) {
        break;
      } else {
        free(ipTable);
        ipTable = NULL;
        break;
      }
    }
  }

// Try to get the Adapters-info table, so we can given useful names to the IP
// addresses we are returning. Have to call GetAdaptersInfo() up to 5 times
// to handle
// the potential race condition between the size-query call and the get-data
// call. I love a well-designed M$ API :^P

  if (ipTable) {
    IP_ADAPTER_INFO * pAdapterInfo = NULL;
    ULONG bufLen = 0;

    for (int i = 0; i < 5; i++) {
      DWORD apRet = GetAdaptersInfo(pAdapterInfo, &bufLen);
      if (apRet == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);  //  in case we had previously allocated it
        pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO *>(malloc(bufLen));
      } else {
        if (apRet == ERROR_SUCCESS) {
          break;
        } else {
          free(pAdapterInfo);
          pAdapterInfo = NULL;
          break;
        }
      }
    }


    for (DWORD i = 0; i < ipTable->dwNumEntries; i++) {
      const MIB_IPADDRROW & row = ipTable->table[i];

      //  Now lookup the appropriate adaptor-name in the pAdaptorInfos,
      //  if we can find it
      const char * name = NULL;
      const char * desc = NULL;

      if (pAdapterInfo) {
        IP_ADAPTER_INFO * next = pAdapterInfo;
        while ((next) && (name == NULL)) {
          IP_ADDR_STRING * ipAddr = &next->IpAddressList;
          while (ipAddr) {
            if (base::inet_aton(ipAddr->IpAddress.String) ==
              ntohl(row.dwAddr)) {
              name = next->AdapterName;
              desc = next->Description;
              break;
            }
            ipAddr = ipAddr->Next;
          }
          next = next->Next;
        }
      }

      char buf[128];
      if (name == NULL) {
        snprintf(buf, sizeof(buf), "unnamed-%lu", i);
        name = buf;
        break;
      }

      boost::uint32_t ipAddr = ntohl(row.dwAddr);
      boost::uint32_t netmask = ntohl(row.dwMask);
      boost::uint32_t baddr = ipAddr & netmask;
      if (row.dwBCastAddr) {
        baddr |= ~netmask;
      }

      char ifaAddrStr[32];
      base::inet_ntoa(ipAddr, ifaAddrStr);
      // netmask retrieved for possible future use
      char maskAddrStr[32];
      base::inet_ntoa(netmask, maskAddrStr);
      char dstAddrStr[32];
      base::inet_ntoa(baddr, dstAddrStr);

      ip_address_tmp = boost::asio::ip::address(
        boost::asio::ip::address().from_string(ifaAddrStr));
      device_struct singledevice;
      singledevice.ip_address = ip_address_tmp;
      singledevice.interface_ = desc;
      // add the device to the vector
      alldevices->push_back(singledevice);
    }   // end for

    free(pAdapterInfo);
    free(ipTable);
  }   // end if (iptable)

#endif  // MAIDSAFE_WIN32
}   // end of get_net_interfaces

bool get_local_address(boost::asio::ip::address *local_address) {
  // get all network interfaces
  std::vector<struct device_struct> alldevices;
  get_net_interfaces(&alldevices);
  if (!alldevices.empty()) {
    // take the first non-bogus IP address
    for (unsigned int i = 0; i < alldevices.size(); i++) {
      if (alldevices[i].ip_address.to_string().substr(0, 2) != "0." &&
          alldevices[i].ip_address.to_string().substr(0, 7) != "169.254" &&
          alldevices[i].ip_address.to_string().substr(0, 4) != "127.") {
        *local_address = alldevices[i].ip_address;
        return true;
      }
    }
  }
  return false;
}

int32_t random_32bit_integer() {
  int32_t result;
  bool success = false;
  while (!success) {
    try {
      CryptoPP::AutoSeededRandomPool rng;
      CryptoPP::Integer rand_num(rng, 32);
      if (!rand_num.IsConvertableToLong()) {
        result = std::numeric_limits<int32_t>::max() +
          static_cast<int32_t>(rand_num.AbsoluteValue().ConvertToLong());
      } else {
        result =  static_cast<int32_t>(
            rand_num.AbsoluteValue().ConvertToLong());
      }
      success = true;
    }
    catch(...) {
    }
  }
  return result;
}

uint32_t random_32bit_uinteger() {
  uint32_t result;
  bool success = false;
  while (!success) {
    try {
      CryptoPP::AutoSeededRandomPool rng;
      CryptoPP::Integer rand_num(rng, 32);
      if (!rand_num.IsConvertableToLong()) {
        result = std::numeric_limits<uint32_t>::max() +
          static_cast<uint32_t>(rand_num.AbsoluteValue().ConvertToLong());
      } else {
        result = static_cast<uint32_t>(
            rand_num.AbsoluteValue().ConvertToLong());
      }
      success = true;
    }
    catch(...) {
    }
  }
  return result;
}

std::vector<std::string> get_local_addresses() {
  // get all network interfaces
  std::vector<std::string> addresses;
  std::vector<struct device_struct> alldevices;
  get_net_interfaces(&alldevices);
  if (!alldevices.empty()) {
    // take the first non-bogus IP address
    for (unsigned int i = 0; i < alldevices.size(); i++) {
      if (alldevices[i].ip_address.to_string().substr(0, 2) != "0." &&
          alldevices[i].ip_address.to_string().substr(0, 4) != "127." &&
          alldevices[i].ip_address.to_string().substr(0, 8) != "169.254.") {
        addresses.push_back(alldevices[i].ip_address.to_string());
      }
    }
  }
  return addresses;
}
}  // namespace base
