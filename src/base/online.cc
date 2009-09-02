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

#include "maidsafe/online.h"

namespace base {

OnlineController* OnlineController::instance() {
  static OnlineController oc;
  return &oc;
}

OnlineController::OnlineController()
    : online_(false), ol_mutex_(), observers_() { }

OnlineController::~OnlineController() {
  online_ = false;
}

boost::uint16_t OnlineController::RegisterObserver(const observer &ob) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  boost::uint16_t id = base::random_32bit_uinteger() % 65536;
  std::pair<std::map<boost::uint16_t, observer>::iterator, bool> ret;
  ret = observers_.insert(std::pair<boost::uint16_t, observer>(id, ob));
  while (!ret.second) {
    id = base::random_32bit_uinteger() % 65536;
    ret = observers_.insert(std::pair<boost::uint16_t, observer>(id, ob));
  }
  return id;
}

void OnlineController::SetOnline(const bool &b) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  online_ = b;
  for (std::map<boost::uint16_t, observer>::iterator it = observers_.begin();
       it != observers_.end(); ++it)
    (*it).second(online_);
}

bool OnlineController::Online() {
  boost::mutex::scoped_lock loch(ol_mutex_);
  return online_;
}

boost::uint16_t OnlineController::ObserversCount() {
  boost::mutex::scoped_lock loch(ol_mutex_);
  return observers_.size();
}

void OnlineController::Reset() {
  observers_.clear();
  SetOnline(false);
}

}  // namespace base
