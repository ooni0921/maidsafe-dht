# Introduction #

We are releasing this code as is at the moment; it **does** work although it's a bit messy just now. We are cleaning and creating an appropriate interface as a matter of urgency. Please feel free to send us [patches](http://code.google.com/p/maidsafe-dht/wiki/Patches) - **we need your help**.

Thanks.

# Items in TODO list #

  1. Allow bandwidth up/download limits, reporting and quotas.
  1. Add checks for change in local and external IP addresses.
  1. Kademlia caching.
  1. A stable delete operation (we are aware that this would extend the current operations of the DHT).
  1. Compilation of [Google-glog](http://code.google.com/p/google-glog/downloads/list) on MinGW to enable logging on Windows.
  1. Implement installer for Linux, Windows and OS/X (CMake handles this effectively).
  1. Remove ALL compiler warnings. Most compiler warnings we have are now in the [cryptopp library](http://www.cryptopp.com). Removal involves submission of the patches to the creators and monitoring of their acceptance.
  1. Get as close to 100% test coverage ASAP.

As we said before, **all help appreciated**. Please check our [patches wiki](http://code.google.com/p/maidsafe-dht/wiki/Patches) for guidelines on the quality of the code expected.