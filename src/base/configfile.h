/*Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef BASE_CONFIGFILE_H_
#define BASE_CONFIGFILE_H_

#include <libconfig.h++>

#include <vector>
#include <string>
#include <iostream>  // NOLINT

/*
Results:
 0: Success
-1: FileNotFound
-2: Parse
-3: Attribute inexistent
-4: Not a list
-5: Empty list
-6: Attribute in list already
-7: Not a string
-8: Attribute exists
-9: Parent inexistent
*/

namespace base {

class ConfigFileHandler {
  private:
    int result_;
    std::string fileName_;
    libconfig::Config config_;
    int readFile();
    int writeFile();

  public:
    explicit ConfigFileHandler(const std::string &fileName)
      : result_(1), fileName_(fileName), config_() {
    }

    //  Full path to attribute expected
    int getAttributeList(const std::string &attributeName,
      std::vector<std::string> &list);

    //  Full path to attribute expected
    int addListAttribute(const std::string &attributeName,
      const std::string &attributeValue);

    //  Full path to parent expected, atomic attribute name expected
    int addAttribute(const std::string &attributeParent,
      const std::string &attributeName, const std::string &attributeValue);

    //  Full path to attribute expected
    int getAttribute(const std::string &attributeName,
      std::string &attributeValue);

    //  Full path to attribute expected
    int modifyAttribute(const std::string &attributeName,
      const std::string &attributeValue);

    //  Full path to parent expected, atomic attribute name expected
    int removeAttribute(const std::string &attributeParent,
      const std::string &attributeName);
};

}   //  namespace
#endif  // BASE_CONFIGFILE_H_
