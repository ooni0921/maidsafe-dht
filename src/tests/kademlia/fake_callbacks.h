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

#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "protobuf/callback_messages.pb.h"

class FakeCallback {
 public:
  FakeCallback() : result_("") {}
  virtual ~FakeCallback() {}
  virtual void CallbackFunc(const std::string& res) = 0;
  virtual void Reset() = 0;
  std::string result() const {return result_;};
 protected:
  std::string result_;
};

class StartNetCallback : public FakeCallback {
  public:
  StartNetCallback():FakeCallback(), result_msg() {}
  virtual ~StartNetCallback() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res))
      result_msg.set_result("F");
    result_ = result_msg.result();
  }
  void Reset() {
    result_msg.Clear();
    result_ = "";
  }
 private:
  net::NetStartResult result_msg;
};

class PingCallback : public FakeCallback {
 public:
  PingCallback():FakeCallback(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res))
      result_msg.set_result(kad::kRpcResultFailure);
    result_ = result_msg.result();
  }
  void Reset() {
    result_msg.Clear();
    result_ = "";
  }
 private:
  kad::PingResponse result_msg;
};

class StoreValueCallback :public FakeCallback {
 public:
  StoreValueCallback():FakeCallback(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  kad::StoreResponse result_msg;
};

class FindCallback : public FakeCallback {
 public:
  FindCallback() : FakeCallback(), result_msg(), values_(), closest_nodes_() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    for (int i = 0; i < result_msg.values_size(); i++)
      values_.push_back(result_msg.values(i));
    for (int i = 0; i < result_msg.closest_nodes_size(); i++)
      closest_nodes_.push_back(result_msg.closest_nodes(i));
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
    values_.clear();
    closest_nodes_.clear();
  };
  std::list<std::string> values() const {return values_;}
  std::list<std::string> closest_nodes() const {return closest_nodes_;}
 private:
  kad::FindResponse result_msg;
  std::list<std::string> values_;
  std::list<std::string> closest_nodes_;
};

class FindNodeCallback : public FakeCallback {
 public:
  FindNodeCallback() : FakeCallback(), result_msg(), contact_("") {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    if (result_msg.has_contact())
      contact_ = result_msg.contact();
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
    contact_ = "";
  };
  std::string contact() const {return contact_;}
 private:
  kad::FindNodeResult result_msg;
  std::string contact_;
};


class GeneralKadCallback : public FakeCallback {
 public:
  GeneralKadCallback():FakeCallback(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  base::GeneralResponse result_msg;
};

class StoreChunkCallback : public FakeCallback {
 public:
  StoreChunkCallback():FakeCallback(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  kad::StoreResponse result_msg;
};

class LoadChunkCallback : public FakeCallback {
 public:
  LoadChunkCallback():FakeCallback(), result_msg(), content_("") {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    } else {
      if (result_msg.has_content())
        content_ = result_msg.content();
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
    content_ = "";
  };
  std::string content() const {return content_;}
 private:
  maidsafe::GetResponse result_msg;
  std::string content_;
};

class UpdateChunkCallback : public FakeCallback {
 public:
  UpdateChunkCallback() : FakeCallback(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  maidsafe::UpdateResponse result_msg;
};

class GetMsgsCallback : public FakeCallback {
 public:
  GetMsgsCallback() : FakeCallback(), messages_(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    } else {
      for (int i = 0; i < result_msg.messages_size(); i++)
        messages_.push_back(result_msg.messages(i));
    }
    result_ = result_msg.result();
  }
  void Reset() {
    result_ = "";
    messages_.clear();
    result_msg.Clear();
  }
  std::list<std::string> messages() const {return messages_;}
 private:
  std::list<std::string> messages_;
  maidsafe::GetMessagesResponse result_msg;
};

class DeleteChunkCallback : public FakeCallback {
 public:
  DeleteChunkCallback() : FakeCallback(), result_msg() {}
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  maidsafe::DeleteResponse result_msg;
};


inline void wait_result(FakeCallback *cb) {
  while (1) {
    {
//      boost::mutex::scoped_lock guard(*mutex);
      if (cb->result() != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
}

