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

#include "base/config.h"
#include "base/calllatertimer.h"
#include "maidsafe/maidsafe-dht.h"

namespace base {

inline bool CompareCallLaterData(const struct CallLaterMap &first,
                          const struct CallLaterMap &second) {
  return (first.time_to_execute < second.time_to_execute);
}

CallLaterTimer::CallLaterTimer()
    : mutex_(),
      calllater_id_(0),
      is_started_(true),
      blocking_routine(),
      calllaters_(),
      cond_() {
  try {
    blocking_routine.reset(new boost::thread(&CallLaterTimer::TryExecute,
                                             this));
  } catch(std::exception &) {
  }
}

CallLaterTimer::~CallLaterTimer() {
  is_started_ = false;
  {
    boost::mutex::scoped_lock guard(mutex_);
    calllaters_.clear();
  }
  cond_.notify_one();
  blocking_routine->join();
  // calllaters_.clear();
}

void CallLaterTimer::TryExecute() {
  while (true) {
//    printf("CallLaterTimer::TryExecute 1\n");
    {
//      printf("CallLaterTimer::TryExecute 2\n");
      boost::mutex::scoped_lock guard(mutex_);
//      printf("CallLaterTimer::TryExecute 3\n");
      while (calllaters_.empty() && is_started_)
        cond_.wait(guard);
//      printf("CallLaterTimer::TryExecute 4\n");
    }
    if (!is_started_) return;
//    printf("CallLaterTimer::TryExecute 5\n");
    mutex_.lock();
//    printf("CallLaterTimer::TryExecute 6 list size(): %d\n",
//        calllaters_.size());
    if (calllaters_.front().time_to_execute <= get_epoch_milliseconds()) {
//      printf("CallLaterTimer::TryExecute 7 list size(): %d\n",
//        calllaters_.size());
      CallLaterMap clm_element = calllaters_.front();
      calllater_func cb = clm_element.cb;
//      printf("CallLaterTimer::TryExecute 8 list size(): %d\n",
//        calllaters_.size());
      calllaters_.pop_front();
//      printf("CallLaterTimer::TryExecute 9 list size(): %d\n",
//        calllaters_.size());
      mutex_.unlock();
      try {
//        printf("CallLaterTimer::TryExecute before CB.\n");
        cb();
//        printf("CallLaterTimer::TryExecute after CB.\n");
      }
      catch(const std::exception &e) {
        // TODO(dan): Logging this.
#ifdef DEBUG
        printf("Exception in TryExecute: %s\n", e.what());
#endif
      }
    } else {
//      printf("CallLaterTimer::TryExecute 11 list size(): %d\n",
//          calllaters_.size());
      mutex_.unlock();
//      printf("CallLaterTimer::TryExecute 12\n");
    }
//    printf("CallLaterTimer::TryExecute 13\n");
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//    printf("CallLaterTimer::TryExecute 14\n");
  }
}

int CallLaterTimer::AddCallLater(boost::uint64_t msecs, calllater_func cb) {
  if ((msecs <=0)||(!is_started_))
    return -1;
  {
    boost::mutex::scoped_lock guard(mutex_);
    calllater_id_ = (calllater_id_+1)%32768;
    struct CallLaterMap clm;
    clm.time_to_execute = get_epoch_milliseconds()+msecs;
    clm.cb = cb;
    clm.calllater_id = calllater_id_;
    calllaters_.push_back(clm);
    calllaters_.sort(CompareCallLaterData);
  }
  cond_.notify_one();
  return calllater_id_;
}

bool CallLaterTimer::CancelOne(int calllater_id) {
  std::list<CallLaterMap>::iterator it;
  boost::mutex::scoped_lock guard(mutex_);
  for (it = calllaters_.begin(); it != calllaters_.end(); it++) {
    if (it->calllater_id == calllater_id) {
      calllaters_.erase(it);
      return true;
    }
  }
  return false;
}

int CallLaterTimer::CancelAll() {
//  printf("CallLaterTimer::CancelAll 1\n");
  boost::mutex::scoped_lock guard(mutex_);
//  printf("CallLaterTimer::CancelAll 2\n");
  int n = calllaters_.size();
//  printf("CallLaterTimer::CancelAll 3\n");
  calllaters_.clear();
//  printf("CallLaterTimer::CancelAll 4\n");
  return n;
}

int CallLaterTimer::list_size() {
  boost::mutex::scoped_lock guard(mutex_);
  return calllaters_.size();
}
}  // namespace base
