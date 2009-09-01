/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface for alternative storage class which Kademlia can use
*               in addition to its own datastore class
* Version:      1.0
* Created:      2009-08-17-15.22.11
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_ALTERNATIVESTORE_H_
#define MAIDSAFE_ALTERNATIVESTORE_H_

#include <string>

namespace base {

class AlternativeStore {
 public:
  AlternativeStore() {}
  virtual ~AlternativeStore() {}
  virtual bool Has(const std::string &key) = 0;
};

}  // namespace base
#endif  // MAIDSAFE_ALTERNATIVESTORE_H_
