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

#ifndef MAIDSAFE_KADEMLIA_KADID_H_
#define MAIDSAFE_KADEMLIA_KADID_H_

#include <boost/cstdint.hpp>
#include <string>
#include <vector>
#include <exception>


namespace kad {

enum error_codes { OUT_OF_RANGE,
                   LLIMIT_GT_ULIMIT,
                   INVALID_STRING,
                   INVALID_RANGE };

enum id_type { MAX_ID,
               RANDOM_ID };

typedef std::vector<unsigned char> id_container;
typedef id_container::size_type id_size_type;

const boost::int16_t ID_BITS_SIZE = 512;

id_size_type bitToByteCount(const id_size_type &bitCount);

class KadIdException : public std::exception {
 public:
  explicit KadIdException(const error_codes &err);
  virtual const char* what() const throw();
  error_codes err_no() const;
 private:
  error_codes err_no_;
};

/**
* @class KadId
* Class used to contain a valid kademlia id of ID_BITS_SIZE, which goes from
* 0 to (2^ID_BITS_SIZE) - 1
*/

class KadId {
 public:
  /**
  * Constructor.  Creates an id equal to 0.
  **/
  KadId();

  /**
  * Constructor.  Creates an id = (2^ID_BITS_SIZE) - 1 or a random id in the
  * interval (0, 2^ID_BITS_SIZE)
  * @param type Type of id to be created (MAX_ID or RANDOM_ID)
  */
  explicit KadId(const id_type &type);

  /**
  * Copy contructor.
  * @param rhs a KadId object
  */
  KadId(const KadId &rhs);

  /**
  * Constructor.  Creates a KadId from a hexadecimal string which can be
  * encoded or not.
  * @param id string representing the kademlia id
  * @param enc flag to tell if string is encoded or not
  * @throw KadIdException if string is not a valid kademlia id of size
  * 2^ID_BITS_SIZE
  */
  KadId(const std::string &id, const bool &enc);

  /**
  * Constructor.  Creates a KadId equal to 2^power.
  * @param power
  * @throw KadIdException if power < 0  or power >= ID_BITS_SIZE
  */
  explicit KadId(const boost::int16_t &power);

  /**
  * Constructor.  Creates a random KadId such that
  * 2^power1 <= id and 2^power2 > id
  * @param power1 power lower limit
  * @param power2 power upper limit
  * @throw KadIdException if power1 or power2 < 0  or
  * power1 or power2 >= ID_BITS_SIZE or power1 > power2
  */
  KadId(const boost::int16_t &power1, const boost::int16_t &power2);

  /**
  * Constructor.  Creates a random KadId such that
  * min < id and max > id
  * @param min lower limit
  * @param max upper limit
  */
  KadId(const KadId &min, const KadId &max);

  /**
  * Splits a range [min, max] to [min, max1] and [min1 max]
  * it is assumed that min = 2^n or 0 and max = 2^m -1 and min < max
  * min1 = ((max + min) / 2) + 1 and max1 = (max + min) /2
  * @param min lower limit of original interval
  * @param max upper limit of original interval
  */
  static void SplitRange(const KadId &min, const KadId &max,
      KadId *max1, KadId *min1);

  // Returns True if id1 is closer to target_id than id2
  /**
  * Checks if id1 is closer in XOR distance to target_id than id2.
  * @param id1 KadId object
  * @param id2 KadId object
  * @param target_id KadId object to which id1 and id2 distance is computed to
  * be compared
  */
  static bool CloserToTarget(const KadId &id1, const KadId &id2,
      const KadId &target_id);

  /**
  * Returns a KadId equal to 2^power -1
  * @param power
  * @throw KadIdException if power < 0  or power >= ID_BITS_SIZE
  */
  static KadId MaxIdUpToPower(const boost::int16_t &power);

  /** Binary representation of the kademlia id.
  * @return A string with the binary representation of the kademlia id
  */
  const std::string ToStringBinary() const;

  /** Hexadecimal representation of the kademlia id.
  * @return An ecoded string with the hex representation of the kademlia id
  */
  const std::string ToStringEncoded() const;

  /** Hexadecimal representation of the kademlia id.
  * @return A string with the hex representation of the kademlia id
  */
  const std::string ToStringDecoded() const;

  const id_container raw_id() const { return raw_id_; }

  // Overloaded operators
  bool operator == (const KadId &rhs) const;
  bool operator != (const KadId &rhs) const;
  bool operator > (const KadId &rhs) const;
  bool operator < (const KadId &rhs) const;
  bool operator >= (const KadId &rhs) const;
  bool operator <= (const KadId &rhs) const;

  /**
  * XOR distance between two kademlia Ids.  XOR bit to bit.
  * @param rhs KadId to which this is XOR
  * @return a KadId object that is equal to this XOR rhs
  */
  const KadId operator ^ (const KadId &rhs) const;
  KadId& operator= (const KadId &rhs);
 private:
  explicit KadId(const id_container &id);
  void GenerateRandomId();
  id_container raw_id_;
};

}  // namespace kad

#endif  // MAIDSAFE_KADEMLIA_KADID_H_
