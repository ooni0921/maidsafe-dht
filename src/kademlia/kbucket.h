/*
Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: haiyang
 */

#ifndef KADEMLIA_KBUCKET_H_
#define KADEMLIA_KBUCKET_H_

#include <list>
#include <vector>
#include <string>
#include "kademlia/kademlia.h"


namespace kad {

class Contact;

class KBucket {
 public:
  // The lower and upper boundary for the range in the 160-bit ID
  // space covered by this k-bucket
  KBucket(const BigInt &range_min, const BigInt &range_max);
  ~KBucket();
  // add a new contact to the k-bucket
  KBucketExitCode AddContact(const Contact &new_contact);
  // return an existing contact pointer with the specified node_id
  bool GetContact(const std::string &node_id, Contact *contact);
  // Returns a list containing up to the first count number of contacts
  // excluding the list of contacts provided.
  void GetContacts(int count, const std::vector<Contact> &exclude_contacts,
      std::vector<Contact> *contacts);
  // remove the existing contact with the specified node_id
  void RemoveContact(const std::string &node_id, const bool &force);
  // Tests whether the specified key (i.e. node ID) is in the range
  // of the 160-bit ID space covered by this k-bucket (in otherwords, it
  // returns whether or not the specified key should be placed in this
  // k-bucket)
  bool KeyInRange(const std::string &key);
  // return the number of contacts in this k-bucket
  int Size() const;
  boost::uint32_t last_accessed() const;
  void set_last_accessed(const boost::uint32_t &time_accessed);
  BigInt range_min() const;
  BigInt range_max() const;

 private:
  boost::uint32_t last_accessed_;
  std::list<Contact> contacts_;
  BigInt range_min_;
  BigInt range_max_;
};
}  // namespace kad

#endif  // KADEMLIA_KBUCKET_H_
