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
 *  Created on: Sep 29, 2008
 *      Author: Jose
 */

#include <boost/random.hpp>
#include <ctime>
#include "kademlia/kademlia.h"
#include "base/utils.h"

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
