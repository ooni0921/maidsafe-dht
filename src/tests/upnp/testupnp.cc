/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 19, 2008
 *      Author: haiyang
 */

#include "upnp/upnp.hpp"
#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/ref.hpp>
#include <boost/intrusive_ptr.hpp>
#include "base/config.h"
#include "maidsafe/maidsafe-dht.h"

using boost::asio::ip::udp;

void on_port_mapping(int mapping, int port
  , std::string const& errmsg, int map_transport){
  if (errmsg == "")
    std::cout << "UPnP port mapped successfully" << std::endl;
  std::cout << "Port mapping result: mapping:" << mapping << ", port" <<port << ", errmsg:"
    << errmsg <<", map_transport"<<map_transport << std::endl;
}

void time_out(libtorrent::io_service *io_service) {
  std::cout << "operation timed out" << std::endl;
  io_service->stop();
}

int main(){
  //udp::endpoint* local_address;
  /*libtorrent::address local_ip;
  if (!base::get_local_address(local_ip)){
    std::cout <<"Failed to get local ip address" << std::endl;
    //local_address = new boost::asio::ip::udp::endpoint(local_ip, 63333);
  }*/
  libtorrent::io_service io_service;
  libtorrent::connection_queue half_open(io_service);
#ifdef MAIDSAFE_WIN32
    // windows XP has a limit on the number of
    // simultaneous half-open TCP connections
    DWORD windows_version = ::GetVersion();
    if ((windows_version & 0xff) >= 6)
    {
      // on vista the limit is 5 (in home edition)
      half_open.limit(4);
    }
    else
    {
      // on XP SP2 it's 10
      half_open.limit(8);
    }
#endif
  boost::asio::deadline_timer timer(io_service);
  std::string user_agent = "haiyang.ma";
  boost::intrusive_ptr<libtorrent::upnp> my_upnp = new libtorrent::upnp(io_service, half_open, libtorrent::address_v4(),
      user_agent,boost::bind(&on_port_mapping, _1, _2, _3, 1), false);
  std::cout <<"discovering the UPnP device..." <<std::endl;
  my_upnp->discover_device();
  timer.expires_from_now(boost::posix_time::seconds(2));
  //timer.async_wait(boost::bind(&libtorrent::io_service::stop, boost::ref(io_service)));
  timer.async_wait(boost::bind(&time_out, &io_service));
  io_service.reset();
  io_service.run();
  std::cout <<"Mapping UDP port..." <<std::endl;
  int udp_map = my_upnp->add_mapping(libtorrent::upnp::udp, 63333, 63335);
  timer.expires_from_now(boost::posix_time::seconds(2));
  //timer.async_wait(boost::bind(&libtorrent::io_service::stop, boost::ref(io_service)));
  timer.async_wait(boost::bind(&time_out, &io_service));
  io_service.reset();
  io_service.run();
  std::cout <<"Deleting the UDP mapped port..." <<std::endl;
  my_upnp->delete_mapping(udp_map);
  timer.expires_from_now(boost::posix_time::seconds(2));
  //timer.async_wait(boost::bind(&libtorrent::io_service::stop, boost::ref(io_service)));
  timer.async_wait(boost::bind(&time_out, &io_service));
  io_service.reset();
  io_service.run();
  std::cout <<"Closing ..." <<std::endl;
  my_upnp->close();
  timer.expires_from_now(boost::posix_time::seconds(2));
  //timer.async_wait(boost::bind(&libtorrent::io_service::stop, boost::ref(io_service)));
  timer.async_wait(boost::bind(&time_out, &io_service));
  io_service.reset();
  io_service.run();
  return 0;
}
