/*Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "base/config.h"
#include "base/utils.h"
#include "base/calllatertimer.h"

namespace base {

bool CompareCallLaterData(const struct CallLaterMap &first,
    const struct CallLaterMap &second) {
  if (first.time_to_execute < second.time_to_execute)
    return true;
  else
    return false;
}

void BlockingRoutine(CallLaterTimer *timer) {
  while (timer->IsStarted()) {
    timer->TryExecute();
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
}

CallLaterTimer::CallLaterTimer(boost::recursive_mutex *mutex)
  : mutex_(mutex), calllater_id_(0), is_started_(true),
  blocking_routine(NULL), calllaters_(NULL) {
  try {
    blocking_routine = new boost::thread(boost::bind(&BlockingRoutine, this));
  }
  catch(std::exception&) {
  }
}

CallLaterTimer::~CallLaterTimer() {
  is_started_ = false;
  blocking_routine->join();
  calllaters_.clear();
  delete blocking_routine;
}

void CallLaterTimer::TryExecute() {
  if ((is_started_)&&(!calllaters_.empty())) {
    base::pd_scoped_lock guard(*mutex_);
    if ((!is_started_)||(calllaters_.empty()))
      return;
    if (calllaters_.front().time_to_execute <= get_epoch_milliseconds()) {
      try {
        calllaters_.front().cb();
      }
      catch(const std::exception &e) {
        // TODO(dan): Logging this.
#ifdef DEBUG
        printf("Exception in TryExecute: %s\n", e.what());
#endif
      }
      calllaters_.pop_front();
    }
  }
}

bool CallLaterTimer::IsStarted() {
  return is_started_;
}

int CallLaterTimer::AddCallLater(boost::uint64_t msecs, calllater_func cb) {
  if ((msecs <=0)||(!is_started_))
    return -1;
  calllater_id_ = (calllater_id_+1)%32768;
  struct CallLaterMap clm;
  clm.time_to_execute = get_epoch_milliseconds()+msecs;
  clm.cb = cb;
  clm.calllater_id = calllater_id_;
  calllaters_.push_back(clm);
  calllaters_.sort(CompareCallLaterData);
  return calllater_id_;
}

void CallLaterTimer::CancelAll() {
  base::pd_scoped_lock guard(*mutex_);
  calllaters_.clear();
}

bool CallLaterTimer::CancelOne(int calllater_id) {
  base::pd_scoped_lock guard(*mutex_);
  std::list<CallLaterMap>::iterator it;
  for (it = calllaters_.begin(); it != calllaters_.end(); it++) {
    if (it->calllater_id == calllater_id) {
      calllaters_.erase(it);
      return true;
    }
  }
  return false;
}

}  // namespace
