/*Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef BASE_SINGLETON_H_
#define BASE_SINGLETON_H_

#include <boost/thread/mutex.hpp>
#include <memory>
namespace base {

typedef boost::mutex::scoped_lock scoped_lock;

template <class T>
class Singleton {
  public:
    static inline T* instance();
    Singleton(void) {}
    ~Singleton(void) {}
    Singleton(const Singleton&) {}
    Singleton & operator=(const Singleton &) {}
    static std::auto_ptr<T> instance_;
    static boost::mutex mutex_;
};

template <class T>
std::auto_ptr<T> Singleton<T>::instance_;

template <class T>
boost::mutex Singleton<T>::mutex_;

template <class T> inline T* Singleton<T>::instance() {
  scoped_lock guard(mutex_);
  if (0 == instance_.get()) {
    if (0 == instance_.get()) {
      instance_.reset(new T);
    }
  }
  return instance_.get();
}

}   // namespace base

#endif  // BASE_SINGLETON_H_
