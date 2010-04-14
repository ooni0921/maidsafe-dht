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

#include "maidsafe/config.h"
#include "base/config.h"
#include "base/calllatertimer.h"
#include "maidsafe/maidsafe-dht.h"

namespace base {

void dummy_timeout_func() {
}

CallLaterTimer::CallLaterTimer() : timers_mutex_(), is_started_(true),
      worker_(), timers_(), io_(), strand_(io_), timer_(io_), calllater_id_(0) {
  timer_.expires_at(boost::posix_time::pos_infin);
  timer_.async_wait(boost::bind(&dummy_timeout_func));
  try {
    worker_.reset(new boost::thread(boost::bind(&boost::asio::io_service::run,
                                    &io_)));
  } catch(const std::exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
  }
}

CallLaterTimer::~CallLaterTimer() {
  {
    boost::mutex::scoped_lock guard(timers_mutex_);
    is_started_ = false;
    timers_.clear();
  }
  io_.stop();
  worker_->join();
}

void CallLaterTimer::ExecuteFunc(calllater_func cb, boost::uint32_t id,
      const boost::system::error_code &ec) {
  if (!ec) {
    cb();
    boost::mutex::scoped_lock guard(timers_mutex_);
    timers_map::iterator it = timers_.find(id);
    if (it != timers_.end()) {
      timers_.erase(it);
    }
  }
}

int CallLaterTimer::AddCallLater(const boost::uint64_t &msecs,
      calllater_func cb) {
  {
    boost::mutex::scoped_lock guard(timers_mutex_);
    if ((msecs == 0) || (!is_started_))
      return -1;

    calllater_id_ = (calllater_id_ + 1) % 32768;
    boost::shared_ptr<boost::asio::deadline_timer> timer(
        new boost::asio::deadline_timer(io_,
        boost::posix_time::milliseconds(msecs)));
    std::pair<timers_map::iterator, bool> p = timers_.insert(timer_pair(
        calllater_id_, timer));
    if (p.second) {
      timer->async_wait(boost::bind(&CallLaterTimer::ExecuteFunc, this, cb,
          calllater_id_, _1));
      return calllater_id_;
    }
  }
  return -1;
}

bool CallLaterTimer::CancelOne(const boost::uint32_t &calllater_id) {
  timers_map::iterator it = timers_.find(calllater_id);
  if (it == timers_.end())
    return false;
  boost::mutex::scoped_lock guard(timers_mutex_);
  it->second->cancel();
  timers_.erase(it);
  return true;
}

int CallLaterTimer::CancelAll() {
  boost::mutex::scoped_lock guard(timers_mutex_);
  int n = timers_.size();
  for (timers_map::iterator it = timers_.begin(); it != timers_.end(); ++it) {
    it->second->cancel();
  }
  timers_.clear();
  return n;
}

size_t CallLaterTimer::list_size() {
  boost::mutex::scoped_lock guard(timers_mutex_);
  return timers_.size();
}
}  // namespace base
