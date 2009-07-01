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

#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/ref.hpp>
#include <boost/intrusive_ptr.hpp>
#include "maidsafe/maidsafe-dht.h"
#include "upnp/upnp.hpp"
#include "base/config.h"


class UpnpTest: public testing::Test {
 public:
  UpnpTest() : mapped_port(0), has_timed_out(false) {}
  void OnPortMapping(int mapping, int port,
                     std::string const& errmsg,
                     int map_transport);
  void OnTimeOut(libtorrent::io_service *io_service);
  int mapped_port;
  bool has_timed_out;
};

void UpnpTest::OnPortMapping(int mapping, int port,
                             std::string const& errmsg,
                             int map_transport) {
  if (errmsg == "") {
    mapped_port = port;
  } else {
    mapped_port = 0;
  }

  printf("Port mapping result:\n\tmapping: %d\n\tport: %d\n\terrmsg: %s\n" \
         "\tmap_transport: %d\n",
         mapping, port, errmsg.c_str(), map_transport);
}

void UpnpTest::OnTimeOut(libtorrent::io_service *io_service) {
  has_timed_out = true;
  io_service->stop();
}

TEST_F(UpnpTest, BEH_UPNP_PortMappingTest) {
  libtorrent::io_service io_service;
  libtorrent::connection_queue half_open(io_service);

#ifdef MAIDSAFE_WIN32
    // windows XP has a limit on the number of
    // simultaneous half-open TCP connections
    DWORD windows_version = ::GetVersion();
    if ((windows_version & 0xff) >= 6) {
      // on vista the limit is 5 (in home edition)
      half_open.limit(4);
    } else {
      // on XP SP2 it's 10
      half_open.limit(8);
    }
#endif

  boost::asio::deadline_timer timer(io_service);
  std::string user_agent = "maidsafe test";
  boost::intrusive_ptr<libtorrent::upnp> my_upnp =
    new libtorrent::upnp(io_service, half_open, libtorrent::address_v4(),
    user_agent,
    boost::bind(&UpnpTest::OnPortMapping, this, _1, _2, _3, 1),
    false);

  printf("Discovering the UPnP device...\n");
  my_upnp->discover_device();

  has_timed_out = false;
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&UpnpTest::OnTimeOut, this, &io_service));

  if (has_timed_out) {
    printf("UPnP device discovery timed out.\n");
    return;
  }

  io_service.reset();
  io_service.run();

  printf("Mapping UDP port...\n");
  int udp_map = my_upnp->add_mapping(libtorrent::upnp::udp, 63333, 63335);

  if (udp_map == -1) {
    printf("UDP port mapping failed immediately.\n");
    return;
  }

  has_timed_out = false;
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&UpnpTest::OnTimeOut, this, &io_service));

  if (has_timed_out) {
    printf("UDP port mapping timed out.\n");
    return;
  }

  io_service.reset();
  io_service.run();

  if (mapped_port == 0) {
    printf("UDP port mapping failed.\n");
    return;
  }

  printf("Port successfully mapped to %d.\n", mapped_port);

  printf("Deleting the UDP mapped port...\n");
  my_upnp->delete_mapping(udp_map);

  has_timed_out = false;
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&UpnpTest::OnTimeOut, this, &io_service));

  ASSERT_FALSE(has_timed_out) << "UDP port mapping deletion timed out.";

  io_service.reset();
  io_service.run();

  printf("Closing UPnP...\n");
  my_upnp->close();

  has_timed_out = false;
  timer.expires_from_now(boost::posix_time::seconds(2));
  timer.async_wait(boost::bind(&UpnpTest::OnTimeOut, this, &io_service));

  ASSERT_FALSE(has_timed_out) << "Closing UPnP timed out.";

  // io_service.reset();
  // io_service.run();

  printf("UPnP test completed successfully.\n");
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
