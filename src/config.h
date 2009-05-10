/*Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef MAIDSAFE_MAIDSAFE_H_
#define MAIDSAFE_MAIDSAFE_H_

#include <boost/cstdint.hpp>
#include <stdint.h>

#include <string>

#include "protobuf/datamaps.pb.h"
#include "protobuf/packet.pb.h"

// system constants
const uint32_t kMinRegularFileSize = 512;
const std::string kHashSize("SHA512");

struct Key_Type {
  Key_Type() : package_type(), id(""), private_key(""), public_key("") {}
  maidsafe::PacketType package_type;
  std::string id;
  std::string private_key;
  std::string public_key;
};

struct bufferpacket_messages {
  bufferpacket_messages() : index(""), message(""), sender(""), type() {}
  std::string index;
  std::string message;
  std::string sender;
  packethandler::MessageType type;
};

enum buffer_packet_type {
  MPID_BP, MAID_BP, PMID_BP
};

const std::string kAnonymousSignedRequest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // NOLINT

enum db_init_flag {CONNECT, CREATE, DISCONNECT};

// struct seh_processed_jobs {
//   std::string path;
//   int exit_code;
//   seh_job_type type;
// };

const std::string kRoot("/");
const std::string kKeysDb("/KeysDb");

const int kRootSubdirSize = 2;
const int kSharesSubdirSize = 2;

const std::string kRootSubdir[kRootSubdirSize][2] = {
  {"/My Files", ""},
  {"/Shares", "c7e625436063a42719208d02ff2bc12498502fd04240d64a4c8b5c8aafb3362ed2302ee117394fb06d291b78dd0195dcb9f371c3806732bdf872b46923079bc8"}  // NOLINT
};

const std::string kSharesSubdir[kSharesSubdirSize][2] = {
  {"/Shares/Private", ""},
//  {"/Shares/Public", "a0590baf0f811834de68fec77950c179595f5ecb5dc3c6abac67dc349714101e40b44531054196b4616f3314cee94d71babb5fbc7010d7fff958d8c8cc54836c"},  // NOLINT
  {"/Shares/Anonymous", "63ed99cc9f91c7dd568247337fd5b479e2cec00e9054ec4c5797c319a80fe3ab07a01dca8200dfd63142b1ed376970bb3a9acd3fa55e9d631d3c0aff42f7660e"}  // NOLINT
};

// const std::string default_dir_[] = {
//   "/Documents",
//   "/Backup",
//   "/Groups",
//   "/Library",
//   "/Maidsafe",
//   "/Music",
//   "/Pictures",
//   "/Public",
//   "/Sites",
//   "/Software",
//   "/Web"
// };
//
const std::string no_compress_type[] =  {
  ".jpg",
  ".jpeg",
  ".jpe",
  ".jfif",
  ".gif",
  ".png",
  ".mp3",
  ".mp4",
  ".0",
  ".000",
  ".7z",
  ".ace",
  ".ain",
  ".alz",
  ".apz",
  ".ar",
  ".arc",
  ".ari",
  ".arj",
  ".axx",
  ".ba",
  ".bh",
  ".bhx",
  ".boo",
  ".bz",
  ".bz2",
  ".bzip2",
  ".c00",
  ".c01",
  ".c02",
  ".car",
  ".cbr",
  ".cbz",
  ".cp9",
  ".cpgz",
  ".cpt",
  ".dar",
  ".dd",
  ".deb",
  ".dgc",
  ".dist",
  ".ecs",
  ".efw",
  ".fdp",
  ".gca",
  ".gz",
  ".gzi",
  ".gzip",
  ".ha",
  ".hbc",
  ".hbc2",
  ".hbe",
  ".hki",
  ".hki1",
  ".hki2",
  ".hki3",
  ".hpk",
  ".hyp",
  ".ice",
  ".ipg",
  ".ipk",
  ".ish",
  ".j",
  ".jgz",
  ".jic",
  ".kgb",
  ".lbr",
  ".lha",
  ".lnx",
  ".lqr",
  ".lzh",
  ".lzm",
  ".lzma",
  ".lzo",
  ".lzx",
  ".md",
  ".mint",
  ".mpkg",
  ".mzp",
  ".p7m",
  ".package",
  ".pae",
  ".pak",
  ".paq6",
  ".paq7",
  ".paq8",
  ".par",
  ".par2",
  ".pbi",
  ".pcv",
  ".pea",
  ".pf",
  ".pim",
  ".pit",
  ".piz",
  ".pkg",
  ".pup",
  ".puz",
  ".pwa",
  ".qda",
  ".r00",
  ".r01",
  ".r02",
  ".r03",
  ".rar",
  ".rev",
  ".rk",
  ".rnc",
  ".rpm",
  ".rte",
  ".rz",
  ".rzs",
  ".s00",
  ".s01",
  ".s02",
  ".s7z",
  ".sar",
  ".sdn",
  ".sea",
  ".sen",
  ".sfs",
  ".sfx",
  ".sh",
  ".shar",
  ".shk",
  ".shr",
  ".sit",
  ".sitx",
  ".spt",
  ".sqx",
  ".sqz",
  ".tar",
  ".tbz2",
  ".tgz",
  ".tlz",
  ".uc2",
  ".uha",
  ".vsi",
  ".wad",
  ".war",
  ".wot",
  ".xef",
  ".xez",
  ".xpi",
  ".xx",
  ".y",
  ".yz",
  ".z",
  ".zap",
  ".zfsendtotarget",
  ".zip",
  ".zix",
  ".zoo",
  ".zz"
};

const std::string kCallbackSuccess("T");
const std::string kCallbackFailure("F");
// config file name
const std::string kConfigFileName("maidsafe.cfg");
const int kMaxPort = 65535;
const int kMinPort = 5000;

const std::string kRpcResultSuccess("T");
const std::string kRpcResultFailure("F");
const int kValidityCheckMinTime(1800);  // 30 min
const int kValidityCheckMaxTime(86400);  // 24 hours
// frequency to execute validity check process
const int kValidityCheckInterval(120);  // 2 minutes
// delay to check partner references
const int kCheckPartnerRefDelay(300);  // 5 minutes
// ValidityCheck Status
const std::string kValidityCheckClean("C");
const std::string kValidityCheckDirty("D");
const int kValidityCheckRetry(2);  // retries for validity check (timeouts)
const int kMinChunkCopies(4);
const int kMaxPingRetries(2);  // max number of ping tries
const int kMaxChunkLoadRetries(3);  // max number of tries to load a chunk
const int kMaxChunkStoreRetries(10);  // max number of tries to store or update
                                     // a chunk
const boost::uint32_t kSaveUpdatesTrigger(100);  // max no of dbs in save queue
                                                 // before running save queue
#endif  // MAIDSAFE_MAIDSAFE_H_
