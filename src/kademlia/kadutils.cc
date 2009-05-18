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

#include <boost/random.hpp>
#include <ctime>
#include "maidsafe/maidsafe-dht.h"

namespace kad {
boost::mp_math::mp_int<> kademlia_distance(
    const std::string &key_one,
    const std::string &key_two) {
  std::string enc_key_one, enc_key_two;
  base::encode_to_hex(key_one, enc_key_one);
  enc_key_one = "0x"+enc_key_one;
  base::encode_to_hex(key_two, enc_key_two);
  enc_key_two = "0x"+enc_key_two;
  boost::mp_math::mp_int<> value_one(enc_key_one);
  boost::mp_math::mp_int<> value_two(enc_key_two);
  return value_one ^ value_two;
}

std::string random_kademlia_id(const boost::mp_math::mp_int<> &min_range,
  const boost::mp_math::mp_int<> &max_range) {
  boost::mt19937 gen;
  gen.seed(static_cast<unsigned int>(base::random_32bit_uinteger()\
    ^static_cast<unsigned int>(std::time(0))));
  boost::mp_math::uniform_mp_int<> big_random(0, max_range - min_range);
  boost::mp_math::mp_int<> rand_num = big_random(gen);
  rand_num = rand_num % (max_range - min_range) + min_range;
  if (rand_num >= max_range)
    rand_num = max_range - 1;
  if (rand_num < min_range)
    rand_num = min_range;
  std::ostringstream os;
  os.setf(std::ios_base::hex, std::ios_base::basefield);
  os << rand_num;
  std::string result;
  std::string temp = os.str();
  if (temp.size() < 2 * kKeySizeBytes) {
    temp = std::string(2 * kKeySizeBytes - temp.size(), '0') + temp;
  }
  base::decode_from_hex(temp, result);
  return result;
}

std::string client_node_id() {
  std::string id(kKeySizeBytes, '\0');
  return id;
}
std::string vault_random_id() {
  boost::mp_math::mp_int<> min_range(0);
  boost::mp_math::mp_int<> max_range(2);
  max_range.pow(kKeySizeBytes*8);
  max_range--;
  return random_kademlia_id(min_range, max_range);
}

}  // namespace
