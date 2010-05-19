/* Copyright (c) 2010 maidsafe.net limited
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

#include "maidsafe/kademlia/kadid.h"
#include <boost/lexical_cast.hpp>
#include <cstdlib>
#include <cstdio>
#include "maidsafe/base/utils.h"


namespace kad {

id_size_type bitToByteCount(const id_size_type &bitCount) {
  id_container::size_type byteCount(bitCount / 8);
  if (bitCount % 8 != 0)
    byteCount++;
  return byteCount;
}

KadIdException::KadIdException(const error_codes &err) : std::exception(),
    err_no_(err) {}

const char* KadIdException::what() const throw() {
  std::string msg("Error: ");
  msg += boost::lexical_cast<std::string>(err_no_);
  switch (err_no_) {
    case OUT_OF_RANGE: msg += ". Power of 2 out of range";
                       break;
    case LLIMIT_GT_ULIMIT: msg += ". Lower limit greater than upper limit";
                           break;
    case INVALID_STRING: msg += ". String is not a decoded or encoded id";
                         break;
    case INVALID_RANGE: msg += ". Min id is greater than max id in range";
                        break;
  }
  return msg.c_str();
}

error_codes KadIdException::err_no() const {
  return err_no_;
}

KadId::KadId() : raw_id_(bitToByteCount(ID_BITS_SIZE), 0) {
}

KadId::KadId(const KadId &rhs) : raw_id_(rhs.raw_id_) {
}

KadId::KadId(const boost::int16_t &power)
    : raw_id_(bitToByteCount(ID_BITS_SIZE), 0) {
  if (power < 0 || power >= ID_BITS_SIZE)
    throw KadIdException(OUT_OF_RANGE);
  boost::int16_t shift = power % 8;
  if (shift != 0) {
    raw_id_[raw_id_.size() - bitToByteCount(power)] += 1 << shift;
  } else {
    raw_id_[raw_id_.size() - bitToByteCount(power) - 1] = 1;
  }
}

KadId::KadId(const boost::int16_t &power1, const boost::int16_t &power2)
      : raw_id_(bitToByteCount(ID_BITS_SIZE), 0) {
  if (power1 >= power2)
    throw KadIdException(LLIMIT_GT_ULIMIT);
  if (power1 < -1 || power2 > ID_BITS_SIZE)
    throw KadIdException(OUT_OF_RANGE);
  id_size_type u_pos(raw_id_.size() - bitToByteCount(power2));
  id_size_type l_pos(0);
  unsigned char l_limit = 1;
  boost::int8_t shift = power1 % 8;
  bool power_ID_BITS_SIZE = false;
  if (power2 == ID_BITS_SIZE)
    power_ID_BITS_SIZE = true;
  if (power1 > -1) {
    if (shift != 0) {
      l_pos = raw_id_.size() - bitToByteCount(power1);
      l_limit = l_limit << shift;
    } else {
      l_pos = raw_id_.size() - bitToByteCount(power1) - 1;
    }
  } else  {
    l_pos = 0;
    l_limit = 0;
  }
  shift = power2 % 8;
  unsigned char u_limit = 1;
  if (shift != 0) {
    u_limit = u_limit << shift;
    raw_id_[u_pos] = base::RandomInt32();
  } else if (u_pos > 0) {
    u_pos--;
  }
  if (u_pos != l_pos) {
    while (!power_ID_BITS_SIZE && u_limit <= raw_id_[u_pos])
      raw_id_[u_pos] = raw_id_[u_pos] >> 1;
  } else {
    while ((!power_ID_BITS_SIZE && u_limit <= raw_id_[u_pos])
           || l_limit > raw_id_[l_pos]) {
      if (l_limit > raw_id_[l_pos]) {
        if (raw_id_[u_pos] == 0) {
          raw_id_[u_pos] = 1;
        } else {
          raw_id_[u_pos] = raw_id_[u_pos] << 1;
        }
      } else {
        raw_id_[u_pos] = raw_id_[u_pos] >> 1;
      }
    }
  }
  for (id_size_type i = u_pos + 1; i < raw_id_.size(); ++i) {
    raw_id_[i] = base::RandomInt32();
    if (i == l_pos) {
      while (raw_id_[i] < l_limit) {
        if (raw_id_[i] == 0) {
          raw_id_[i] = 1;
        } else {
          raw_id_[i] = raw_id_[i] << 1;
        }
      }
    }
  }
}

KadId::KadId(const std::string &id, const bool &enc) : raw_id_() {
  if (enc) {
    std::string tmp(base::DecodeFromHex(id));
    id_container tmp_vec(tmp.begin(), tmp.end());
    if (tmp_vec.size() != bitToByteCount(ID_BITS_SIZE)) {
      throw KadIdException(INVALID_STRING);
    }
    raw_id_ = tmp_vec;
  } else {
    id_container tmp_vec(id.begin(), id.end());
    if (tmp_vec.size() != bitToByteCount(ID_BITS_SIZE)) {
      throw KadIdException(INVALID_STRING);
    }
    raw_id_ = tmp_vec;
  }
}

KadId::KadId(const id_container &id) : raw_id_(id) {
}

KadId::KadId(const id_type &type)
      : raw_id_(bitToByteCount(ID_BITS_SIZE), 0xff) {
  switch (type) {
    case RANDOM_ID: GenerateRandomId();
                    break;
    default: break;
  }
}

KadId::KadId(const KadId &min, const KadId &max)
      : raw_id_(bitToByteCount(ID_BITS_SIZE), 0) {
  if (min > max) {
    throw KadIdException(INVALID_RANGE);
  } else if (min == max) {
    raw_id_ = min.raw_id_;
  } else {
    id_size_type min_non_zero_indx(0);
    id_container::const_iterator it = min.raw_id_.begin();
    while (it != --min.raw_id_.end() && (*it) == 0) {
      ++min_non_zero_indx;
      ++it;
    }
    id_size_type max_non_zero_indx(0);
    it = max.raw_id_.begin();
    while (it != max.raw_id_.end() && (*it) == 0) {
      ++max_non_zero_indx;
      ++it;
    }
    raw_id_[max_non_zero_indx] = base::RandomInt32();
    if (max_non_zero_indx != min_non_zero_indx) {
      id_size_type indx = max_non_zero_indx;
      while (raw_id_[indx] >= max.raw_id_[max_non_zero_indx]) {
        --raw_id_[indx];
      }
      bool all_zeros = (raw_id_[indx] == 0) ? true : false;
      ++indx;
      while (indx < raw_id_.size() && all_zeros &&
             indx > min_non_zero_indx) {
        raw_id_[indx] = base::RandomInt32();
        all_zeros = (raw_id_[indx] == 0) ? true : false;
        ++indx;
      }
      if (!all_zeros) {
        for (id_size_type i = indx; i < raw_id_.size(); ++i) {
          raw_id_[i] = base::RandomInt32();
        }
      } else if (indx < raw_id_.size()) {
        // indx == min_non_zero_indx
        raw_id_[indx] = base::RandomInt32();
        while (raw_id_[indx] <= min.raw_id_[min_non_zero_indx]) {
          ++raw_id_[indx];
        }
        for (id_size_type i = ++indx; i < raw_id_.size(); ++i) {
          raw_id_[i] = base::RandomInt32();
        }
      }
    } else {
      while (raw_id_[max_non_zero_indx] >= max.raw_id_[max_non_zero_indx]) {
        --raw_id_[max_non_zero_indx];
      }
      while (raw_id_[min_non_zero_indx] <= min.raw_id_[min_non_zero_indx]) {
          ++raw_id_[min_non_zero_indx];
      }
      for (id_size_type i = ++min_non_zero_indx; i < raw_id_.size(); ++i) {
          raw_id_[i] = base::RandomInt32();
      }
    }
  }
}

void KadId::GenerateRandomId() {
  for (id_container::iterator it = raw_id_.begin(); it != raw_id_.end(); ++it) {
    (*it) = base::RandomInt32();
  }
}

const std::string KadId::ToStringEncoded() const {
  std::string value(raw_id_.begin(), raw_id_.end());
  return base::EncodeToHex(value);
}

const std::string KadId::ToStringBinary() const {
  std::string enc(ToStringEncoded());
  std::string res;
  for (size_t i = 0; i < enc.size(); ++i) {
    std::string tmp_str;
    switch (enc[i]) {
      case '0': tmp_str = "0000"; break;
      case '1': tmp_str = "0001"; break;
      case '2': tmp_str = "0010"; break;
      case '3': tmp_str = "0011"; break;
      case '4': tmp_str = "0100"; break;
      case '5': tmp_str = "0101"; break;
      case '6': tmp_str = "0110"; break;
      case '7': tmp_str = "0111"; break;
      case '8': tmp_str = "1000"; break;
      case '9': tmp_str = "1001"; break;
      case 'a': tmp_str = "1010"; break;
      case 'b': tmp_str = "1011"; break;
      case 'c': tmp_str = "1100"; break;
      case 'd': tmp_str = "1101"; break;
      case 'e': tmp_str = "1110"; break;
      case 'f': tmp_str = "1111"; break;
    }
    res += tmp_str;
  }
  return res;
}

const std::string KadId::ToStringDecoded() const {
  std::string res(raw_id_.begin(), raw_id_.end());
  return res;
}

const KadId KadId::operator ^ (const KadId &rhs) const {
  id_container res(bitToByteCount(ID_BITS_SIZE));
  for (id_size_type i = 0; i < raw_id_.size(); ++i)
    res[i] = raw_id_[i] ^ rhs.raw_id_[i];
  return KadId(res);
}

bool KadId::operator == (const KadId &rhs) const {
  return (this->raw_id() == rhs.raw_id());
}

bool KadId::operator != (const KadId &rhs) const {
  return !(*this == rhs);
}

bool KadId::operator > (const KadId &rhs) const {
  return (!((*this) < rhs) && ((*this) != rhs));
}

bool KadId::operator >= (const KadId &rhs) const {
  return !((*this) < rhs);
}

bool KadId::operator < (const KadId &rhs) const {
  id_container rhs_id = rhs.raw_id();
  id_size_type index(0);
  while (index < raw_id_.size() && raw_id_[index] == rhs_id[index]) {
    ++index;
  }
  if (index == raw_id_.size()) {
    // they are equal
    return false;
  }
  return raw_id_[index] < rhs_id[index];
}

bool KadId::operator <= (const KadId &rhs) const {
  return !((*this) > rhs);
}

KadId& KadId::operator = (const KadId &rhs) {
  this->raw_id_ = rhs.raw_id_;
  return *this;
}

void KadId::SplitRange(const KadId &min, const KadId &max, KadId *max1,
      KadId *min1) {
  if (min >= max)
    throw KadIdException(INVALID_RANGE);
  id_container min_id(min.raw_id()), max_id(max.raw_id());
  id_size_type first_diff_bit = 0;
  for (; first_diff_bit < min_id.size(); ++first_diff_bit) {
    if (min_id[first_diff_bit] != max_id[first_diff_bit])
     break;
  }
  id_container max1_id(max_id), min1_id(min_id);
  max1_id[first_diff_bit] =
      (max1_id[first_diff_bit] + min1_id[first_diff_bit]) >> 1;
  min1_id[first_diff_bit] = max1_id[first_diff_bit] + 1;
  KadId tmp_id1(max1_id), tmp_id2(min1_id);
  *max1 = tmp_id1;
  *min1 = tmp_id2;
}

bool KadId::CloserToTarget(const KadId &id1, const KadId &id2,
      const KadId &target_id) {
  id_container r_id1 = id1.raw_id();
  id_container r_id2 = id2.raw_id();
  id_container t_id = target_id.raw_id();
  for (id_size_type i = 0; i < r_id1.size(); ++i) {
    unsigned char res1 = r_id1[i] ^ t_id[i];
    unsigned char res2 = r_id2[i] ^ t_id[i];
    if (res1 != res2)
      return res1 < res2;
  }
  return false;
}

KadId KadId::MaxIdUpToPower(const boost::int16_t &power) {
  if (power < 0 || power >= ID_BITS_SIZE)
    throw KadIdException(OUT_OF_RANGE);
  id_container id(bitToByteCount(ID_BITS_SIZE), 0);
  boost::int16_t shift = power % 8;
  id_size_type pos = id.size() - bitToByteCount(power);
  if (shift != 0) {
    for (boost::int16_t i = 0; i < shift;++i) {
      id[pos] += 1 << i;
    }
    ++pos;
  }
  for (id_size_type i = pos; i < id.size(); ++i) {
    id[i] = 0xff;
  }
  return KadId(id);
}
}
