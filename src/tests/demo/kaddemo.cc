/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for base/calllatertimer.cc
* Version:      1.0
* Created:      2009-06-12-02.54.48
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <signal.h>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <fstream>
#include "maidsafe/config.h"
#include "maidsafe/maidsafe-dht.h"
#include "tests/demo/commands.h"
#include "protobuf/contact_info.pb.h"
#include "protobuf/general_messages.pb.h"

namespace po = boost::program_options;

class JoinCallback {
 public:
  JoinCallback() : result_arrived_(false), success_(false) {}
  void Callback(const std::string &result) {
    base::GeneralResponse msg;
    if (!msg.ParseFromString(result))
      success_ = false;
    else if (msg.result() == kad::kRpcResultSuccess)
      success_ = true;
    else
      success_ = false;
    result_arrived_ = true;
  }
  bool result_arrived() const { return result_arrived_; }
  bool success() const { return success_; }
 private:
  bool result_arrived_, success_;
};

void conflicting_options(const po::variables_map& vm, const char* opt1,
    const char* opt2) {
  if (vm.count(opt1) && !vm[opt1].defaulted()
      && vm.count(opt2) && !vm[opt2].defaulted())
    throw std::logic_error(std::string("Conflicting options '")  + opt1 +
        "' and '" + opt2 + "'.");
}

/* Function used to check that of 'for_what' is specified, then
   'required_option' is specified too. */
void option_dependency(const po::variables_map& vm,
    const char* for_what, const char* required_option) {
  if (vm.count(for_what) && !vm[for_what].defaulted())
    if (vm.count(required_option) == 0 || vm[required_option].defaulted())
      throw std::logic_error(std::string("Option '") + for_what
          + "' requires option '" + required_option + "'.");
}

bool kadconfig_empty(const std::string &path) {
  base::KadConfig kadconfig;
  try {
    std::ifstream input(path.c_str(), std::ios::in | std::ios::binary);
    if (!kadconfig.ParseFromIstream(&input)) {;
      return true;
    }
    input.close();
    if (kadconfig.contact_size() == 0)
      return true;
  }
  catch (const std::exception &) {
    return true;
  }
  return false;
}

bool write_to_kadconfig(const std::string &path, const std::string &node_id,
    const std::string &ip, const boost::uint16_t &port,
    const std::string &local_ip, const boost::uint16_t &local_port) {
  base::KadConfig kadconfig;
  try {
    base::KadConfig::Contact *ctc = kadconfig.add_contact();
    ctc->set_ip(ip);
    ctc->set_node_id(node_id);
    ctc->set_port(port);
    ctc->set_local_ip(local_ip);
    ctc->set_local_port(local_port);
    std::fstream output(path.c_str(), std::ios::out | std::ios::trunc
        | std::ios::binary);
    if (!kadconfig.SerializeToOstream(&output)) {
      output.close();
      return false;
    }
    output.close();
  }
    catch (const std::exception &) {
    return false;
  }
  return boost::filesystem::exists(path);
}


volatile int ctrlc_pressed = 0;

void ctrlc_handler(int) {
  ctrlc_pressed = 1;
}

void printf_info(kad::ContactInfo info) {
  kad::Contact ctc(info);
  printf("Node info: %s", ctc.ToString().c_str());
}

inline void executecb(base::callback_func_type cb) {
  //boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  cb("MIERDA");
}

int main(int argc, char **argv) {
  try {
    std::string logpath, kadconfigpath, bs_ip, bs_id, ext_ip, configfile,
        bs_local_ip;
    boost::uint16_t bs_port, bs_local_port, port(0), ext_port;
    bool first_node = false;
    po::options_description desc("Options");
    desc.add_options()
      ("help,h", "Print options informations and exit.")
      ("logfilepath,l", po::value(&logpath)->default_value(logpath),
        "Path of logfile")
      ("verbose,v", po::bool_switch(), "Print log to console.")
      ("kadconfigfile,k", po::value(&kadconfigpath)->default_value(kadconfigpath),
        "Complete pathname of kadconfig file. Default is KNode<port>/.kadconfig")
      ("client,c", po::bool_switch(), "Start the node as a client node.")
      ("port,p", po::value(&port)->default_value(port),
        "Local port to start node.  Default is 0, that starts in random port.")
      ("bs_ip", po::value(&bs_ip), "Bootstrap Node ip")
      ("bs_port", po::value(&bs_port), "Bootstrap Node port")
      ("bs_local_ip", po::value(&bs_local_ip), "Bootstrap Node local ip")
      ("bs_local_port", po::value(&bs_local_port), "Bootstrap Node local port")
      ("bs_id", po::value(&bs_id), "Bootstrap Node id")
      ("upnp", po::bool_switch(), "Use UPnP for Nat Traversal")
      ("port_fw", po::bool_switch(), "Manually port forwared local port")
      ("externalip", po::value(&ext_ip),
        "Node's external ip.  Use only when it is the first node in the network.")
      ("externalport", po::value(&ext_port),
          "Node's external ip.  Use only when it is the first node in the network.")
      ("noconsole", po::bool_switch(),
        "Do not have access to kademlia functions (store/load/ping) after node startup")
//      ("configfile", po::value(&configfile),
//        "Pathname to config file to get port and nodeid from previous instance.")
    ;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }
    option_dependency(vm, "bs_id", "bs_ip");
    option_dependency(vm, "bs_ip", "bs_id");
    option_dependency(vm, "bs_id", "bs_port");
    option_dependency(vm, "bs_port", "bs_id");
    option_dependency(vm, "bs_id", "bs_local_ip");
    option_dependency(vm, "bs_id", "bs_local_port");
    option_dependency(vm, "bs_local_ip", "bs_id");
    option_dependency(vm, "bs_local_port", "bs_id");
    option_dependency(vm, "externalip", "externalport");
    option_dependency(vm, "externalport", "externalip");
    option_dependency(vm, "externalport", "port");
    conflicting_options(vm, "upnp", "port_fw");
    conflicting_options(vm, "client", "noconsole");
    conflicting_options(vm, "bs_id", "externalip");
    conflicting_options(vm, "verbose", "logfilepath");

    if(vm.count("externalip"))
      first_node = true;

    // checking if path of kadconfigfile exists
    if (vm.count("kadconfigfile")) {
      kadconfigpath = vm["kadconfigfile"].as<std::string>();
      boost::filesystem::path kadconfig(kadconfigpath);
      if (!boost::filesystem::exists(kadconfig.parent_path())) {
        try {
          boost::filesystem::create_directories(kadconfig.parent_path());
          if (!first_node)
            if (!vm.count("bs_id")) {
              printf("No bootsrapping info.\n");
              return 1;
            }
        }
        catch(const std::exception &) {
          if (!first_node)
            if (!vm.count("bs_id")) {
              printf("No bootsrapping info.\n");
              return 1;
            }
        }
      } else {
        if (kadconfig_empty(kadconfigpath) && !vm.count("bs_id")) {
          printf("No bootsrapping info.\n");
          return 1;
        }
      }
    } else {
      if (!first_node)
        if (!vm.count("bs_id")) {
          printf("No bootsrapping info.\n");
          return 1;
        }
    }

    // setting log
    google::InitGoogleLogging(argv[0]);
#ifndef HAVE_GLOG
    bool FLAGS_logtostderr;
    std::string FLAGS_log_dir;
#endif
    if (vm.count("logfilepath")) {
      FLAGS_log_dir = vm["logfilepath"].as<std::string>();
    } else {
      FLAGS_logtostderr = vm["verbose"].as<bool>();
    }
    // Starting transport on port
    port = vm["port"].as<boost::uint16_t>();
    boost::shared_ptr<rpcprotocol::ChannelManager> chmanager(
        new rpcprotocol::ChannelManager);
    kad::node_type type;
    if (vm["client"].as<bool>())
      type = kad::CLIENT;
    else
      type = kad::VAULT;
    kad::KNode node(chmanager, type, "", "", vm["upnp"].as<bool>(),
        vm["port_fw"].as<bool>());
    if (0 != chmanager->StartTransport(port, boost::bind(
          &kad::KNode::HandleDeadRendezvousServer, &node, _1))) {
      printf("Unable to start node on port %d\n", port);
      return 1;
    }
    // setting kadconfig file if it was not in the options
    if (kadconfigpath == "") {
      kadconfigpath = "KnodeInfo" + base::itos(chmanager->external_port());
      boost::filesystem::create_directories(kadconfigpath);
      kadconfigpath += "/.kadconfig";
    }

    // if not the first vault, write to kadconfig file bootstrapping info
    // if provided in options
    if (!first_node && vm.count("bs_id")) {
      printf("writting to %s\n", kadconfigpath.c_str());
      if(!write_to_kadconfig(kadconfigpath, vm["bs_id"].as<std::string>(),
          vm["bs_ip"].as<std::string>(), vm["bs_port"].as<boost::uint16_t>(),
          vm["bs_ip"].as<std::string>(), vm["bs_port"].as<boost::uint16_t>())) {
        printf("unable to write kadconfig file to %s\n", kadconfigpath.c_str());
        chmanager->StopTransport();
        return 1;
      }
    }

    // Joining the node to the network
    JoinCallback cb;
    if (first_node)
      node.Join(kadconfigpath, vm["externalip"].as<std::string>(),
          vm["externalport"].as<boost::uint16_t>(), boost::bind(
          &JoinCallback::Callback, &cb, _1));
    else
      node.Join(kadconfigpath, boost::bind(&JoinCallback::Callback, &cb, _1));
    while (!cb.result_arrived())
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    // Checking result of callback
    if (!cb.success()) {
      printf("Failed to join node to the network\n");
      chmanager->StopTransport();
      return 1;
    }
    // Printing Node Info
    printf_info(node.contact_info());

    if (!vm["noconsole"].as<bool>()) {
      kaddemo::Commands cmds(&node, 16);
      cmds.Run();
    } else {
      printf("=====================================\n");
      printf("Press Ctrl+C to exit\n");
      printf("=====================================\n\n");
      signal(SIGINT, ctrlc_handler);
	    while (!ctrlc_pressed) {
        boost::this_thread::sleep(boost::posix_time::seconds(1));
      }
    }
    node.StopRvPing();
    node.Leave();
    chmanager->StopTransport();
    printf("\nNode Stopped successfully\n");
  }
  catch(std::exception &e) {
    printf("Error: %s\n", e.what());
    return 1;
  }

  return 0;
}

