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

#include "kademlia/kbucket.h"
#include "kademlia/contact.h"


namespace kad {

KBucket::KBucket(const BigInt &range_min, const BigInt &range_max)
    : last_accessed_(0), contacts_(), range_min_(range_min),
    range_max_(range_max) {}

KBucket::~KBucket() {
  contacts_.clear();
}

bool KBucket::KeyInRange(const std::string &key) {
  std::string key_enc;
  if (!base::encode_to_hex(key, key_enc))
    return false;
  key_enc = "0x"+key_enc;
  BigInt key_val(key_enc);
  return static_cast<bool>((range_min_ <= key_val) && (key_val < range_max_));
}

int KBucket::Size() const { return contacts_.size(); }

boost::uint32_t KBucket::last_accessed() const { return last_accessed_; }

void KBucket::set_last_accessed(const boost::uint32_t &time_accessed) {
  last_accessed_  = time_accessed;
}

KBucketExitCode KBucket::AddContact(const Contact &new_contact) {
  std::string contact_info;
  Contact new_contact_local;
  new_contact_local = new_contact;
  if (!new_contact_local.SerialiseToString(&contact_info))
    return FAIL;
  int position = -1;
  int i = 0;
  // Check if the contact is already in the kbucket to remove it from
  // it and adding it at the top of it
  for (std::list<Contact>::iterator it = contacts_.begin();
      it != contacts_.end()&& position == -1; it++) {
    Contact current_element = *it;
    if (new_contact_local == current_element)
      position = i;
    i++;
  }
  if (position != -1) {
    std::list<Contact>::iterator it = contacts_.begin();
    std::advance(it, position);
    contacts_.erase(it);
    // std::cout << "erasing contact" << std::endl;
  }

  if (static_cast<boost::uint16_t>(Size()) == K)
    return FULL;

  contacts_.push_front(new_contact_local);
  return SUCCEED;
}

void KBucket::RemoveContact(const std::string &node_id, const bool &force) {
  int position = -1;
  int i = 0;
  for (std::list<Contact>::iterator it = contacts_.begin();
    it != contacts_.end(); it++) {
    Contact current_element = *it;
    if (current_element.node_id() == node_id) {
      position = i;
    }
    i++;
  }

  if (position != -1) {
    std::list<Contact>::iterator it = contacts_.begin();
    std::advance(it, position);
    Contact current_element = *it;
    current_element.IncreaseFailed_RPC();
    contacts_.erase(it);
    if (current_element.failed_rpc() <= kFailedRpc && !force) {
      std::list<Contact>::iterator new_it = contacts_.begin();
      std::advance(new_it, position);
      contacts_.insert(new_it, current_element);
    }
  }
}

bool KBucket::GetContact(const std::string &node_id, Contact *contact) {
  bool result = false;
  for (std::list<Contact>::iterator it = contacts_.begin();
    it != contacts_.end() && !result; it++) {
    Contact current_element = *it;
    if (current_element.node_id() == node_id) {
      *contact = current_element;
      result = true;
    }
  }
  return result;
}

void KBucket::GetContacts(int count, const std::vector<Contact>
  &exclude_contacts, std::vector<Contact> *contacts) {
    bool insert;
    int i = 0;
    for (std::list<Contact>::iterator it = contacts_.begin();
      it != contacts_.end() && i < count; it++) {
      insert = true;
      Contact current_element = *it;
      for (int j = 0; j < (static_cast<int>(exclude_contacts.size())) && insert;
          j++) {
        if (current_element.node_id() == exclude_contacts[j].node_id())
          insert = false;
      }
      if (insert) {
        contacts->push_back(current_element);
        i++;
      }
    }
}
BigInt KBucket::range_min() const { return range_min_; }
BigInt KBucket::range_max() const { return range_max_; }
}  // namespace kad
