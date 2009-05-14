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

#ifndef KADEMLIA_KADUTILS_H_
#define KADEMLIA_KADUTILS_H_

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif

#include <boost/mp_math/mp_int.hpp>
#include <string>

namespace kad {
// kademlia distance the input of the kademlia keys must not be encoded
boost::mp_math::mp_int<> kademlia_distance(
    const std::string &key_one,
    const std::string &key_two);

std::string random_kademlia_id(const boost::mp_math::mp_int<> &min_range,
  const boost::mp_math::mp_int<> &max_range);

std::string client_node_id();
std::string vault_random_id();

}  // namespace base

#endif  // KADEMLIA_KADUTILS_H_
