// Generated by the protocol buffer compiler.  DO NOT EDIT!

#include "datamaps.pb.h"
#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format_inl.h>

namespace maidsafe {

namespace {

const ::google::protobuf::Descriptor* Key_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  Key_reflection_ = NULL;
const ::google::protobuf::Descriptor* DataMap_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  DataMap_reflection_ = NULL;
const ::google::protobuf::Descriptor* MetaDataMap_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  MetaDataMap_reflection_ = NULL;
const ::google::protobuf::Descriptor* MetaData_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  MetaData_reflection_ = NULL;
const ::google::protobuf::Descriptor* Chunk_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  Chunk_reflection_ = NULL;
const ::google::protobuf::Descriptor* ShareFromMe_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  ShareFromMe_reflection_ = NULL;
const ::google::protobuf::Descriptor* ShareToMe_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  ShareToMe_reflection_ = NULL;
const ::google::protobuf::Descriptor* ShareToMeBufferMessage_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  ShareToMeBufferMessage_reflection_ = NULL;
const ::google::protobuf::Descriptor* DataAtlas_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  DataAtlas_reflection_ = NULL;
const ::google::protobuf::EnumDescriptor* itemtype_descriptor_ = NULL;
const ::google::protobuf::EnumDescriptor* ShareOperation_descriptor_ = NULL;
const ::google::protobuf::EnumDescriptor* PacketType_descriptor_ = NULL;

}  // namespace


void protobuf_BuildDesc_datamaps_2eproto_AssignGlobalDescriptors(const ::google::protobuf::FileDescriptor* file) {
  Key_descriptor_ = file->message_type(0);
  Key::default_instance_ = new Key();
  static const int Key_offsets_[4] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Key, id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Key, type_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Key, private_key_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Key, public_key_),
  };
  Key_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      Key_descriptor_,
      Key::default_instance_,
      Key_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Key, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Key, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(Key));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    Key_descriptor_, Key::default_instance_);
  DataMap_descriptor_ = file->message_type(1);
  DataMap::default_instance_ = new DataMap();
  static const int DataMap_offsets_[6] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, file_hash_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, se_version_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, chunk_name_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, encrypted_chunk_name_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, chunk_size_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, compression_on_),
  };
  DataMap_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      DataMap_descriptor_,
      DataMap::default_instance_,
      DataMap_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataMap, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(DataMap));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    DataMap_descriptor_, DataMap::default_instance_);
  MetaDataMap_descriptor_ = file->message_type(2);
  MetaDataMap::default_instance_ = new MetaDataMap();
  static const int MetaDataMap_offsets_[11] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, display_name_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, type_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, file_hash_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, stats_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, tag_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, file_size_high_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, file_size_low_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, creation_time_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, last_modified_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, last_access_),
  };
  MetaDataMap_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      MetaDataMap_descriptor_,
      MetaDataMap::default_instance_,
      MetaDataMap_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaDataMap, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(MetaDataMap));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    MetaDataMap_descriptor_, MetaDataMap::default_instance_);
  MetaData_descriptor_ = file->message_type(3);
  MetaData::default_instance_ = new MetaData();
  static const int MetaData_offsets_[5] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, ms_path_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, file_hash_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, stats_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, file_size_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, outname_),
  };
  MetaData_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      MetaData_descriptor_,
      MetaData::default_instance_,
      MetaData_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(MetaData, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(MetaData));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    MetaData_descriptor_, MetaData::default_instance_);
  Chunk_descriptor_ = file->message_type(4);
  Chunk::default_instance_ = new Chunk();
  static const int Chunk_offsets_[3] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Chunk, compression_type_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Chunk, chunklet_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Chunk, pre_compression_chunklet_size__),
  };
  Chunk_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      Chunk_descriptor_,
      Chunk::default_instance_,
      Chunk_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Chunk, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Chunk, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(Chunk));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    Chunk_descriptor_, Chunk::default_instance_);
  ShareFromMe_descriptor_ = file->message_type(5);
  ShareFromMe::default_instance_ = new ShareFromMe();
  static const int ShareFromMe_offsets_[5] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, share_id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, share_name_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, owner_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, meta_data_map_id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, users_),
  };
  ShareFromMe_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      ShareFromMe_descriptor_,
      ShareFromMe::default_instance_,
      ShareFromMe_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareFromMe, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(ShareFromMe));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    ShareFromMe_descriptor_, ShareFromMe::default_instance_);
  ShareToMe_descriptor_ = file->message_type(6);
  ShareToMe::default_instance_ = new ShareToMe();
  static const int ShareToMe_offsets_[5] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, share_id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, share_name_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, owner_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, mdms_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, dms_),
  };
  ShareToMe_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      ShareToMe_descriptor_,
      ShareToMe::default_instance_,
      ShareToMe_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMe, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(ShareToMe));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    ShareToMe_descriptor_, ShareToMe::default_instance_);
  ShareToMeBufferMessage_descriptor_ = file->message_type(7);
  ShareToMeBufferMessage::default_instance_ = new ShareToMeBufferMessage();
  static const int ShareToMeBufferMessage_offsets_[6] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, share_id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, share_name_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, owner_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, op_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, mdms_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, dms_),
  };
  ShareToMeBufferMessage_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      ShareToMeBufferMessage_descriptor_,
      ShareToMeBufferMessage::default_instance_,
      ShareToMeBufferMessage_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ShareToMeBufferMessage, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(ShareToMeBufferMessage));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    ShareToMeBufferMessage_descriptor_, ShareToMeBufferMessage::default_instance_);
  DataAtlas_descriptor_ = file->message_type(8);
  DataAtlas::default_instance_ = new DataAtlas();
  static const int DataAtlas_offsets_[6] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, root_db_key_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, keys_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, mdms_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, dms_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, offered_share_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, accepted_share_),
  };
  DataAtlas_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      DataAtlas_descriptor_,
      DataAtlas::default_instance_,
      DataAtlas_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(DataAtlas, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      sizeof(DataAtlas));
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    DataAtlas_descriptor_, DataAtlas::default_instance_);
  itemtype_descriptor_ = file->enum_type(0);
  ShareOperation_descriptor_ = file->enum_type(1);
  PacketType_descriptor_ = file->enum_type(2);
  Key::default_instance_->InitAsDefaultInstance();
  DataMap::default_instance_->InitAsDefaultInstance();
  MetaDataMap::default_instance_->InitAsDefaultInstance();
  MetaData::default_instance_->InitAsDefaultInstance();
  Chunk::default_instance_->InitAsDefaultInstance();
  ShareFromMe::default_instance_->InitAsDefaultInstance();
  ShareToMe::default_instance_->InitAsDefaultInstance();
  ShareToMeBufferMessage::default_instance_->InitAsDefaultInstance();
  DataAtlas::default_instance_->InitAsDefaultInstance();
}

void protobuf_BuildDesc_datamaps_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  ::google::protobuf::DescriptorPool* pool =
    ::google::protobuf::DescriptorPool::internal_generated_pool();

  pool->InternalBuildGeneratedFile(
    "\n\016datamaps.proto\022\010maidsafe\"^\n\003Key\022\n\n\002id\030"
    "\001 \002(\t\022\"\n\004type\030\002 \002(\0162\024.maidsafe.PacketTyp"
    "e\022\023\n\013private_key\030\003 \002(\t\022\022\n\npublic_key\030\004 \002"
    "(\t\"\225\001\n\007DataMap\022\021\n\tfile_hash\030\001 \002(\t\022\022\n\nse_"
    "version\030\002 \001(\t\022\022\n\nchunk_name\030\003 \003(\t\022\034\n\024enc"
    "rypted_chunk_name\030\004 \003(\t\022\022\n\nchunk_size\030\005 "
    "\003(\004\022\035\n\016compression_on\030\006 \001(\010:\005false\"\362\001\n\013M"
    "etaDataMap\022\n\n\002id\030\001 \002(\005\022\024\n\014display_name\030\002"
    " \002(\t\022 \n\004type\030\003 \002(\0162\022.maidsafe.itemtype\022\021"
    "\n\tfile_hash\030\004 \003(\t\022\r\n\005stats\030\005 \001(\t\022\013\n\003tag\030"
    "\006 \001(\t\022\026\n\016file_size_high\030\007 \001(\005\022\025\n\rfile_si"
    "ze_low\030\010 \001(\005\022\025\n\rcreation_time\030\t \001(\005\022\025\n\rl"
    "ast_modified\030\n \001(\005\022\023\n\013last_access\030\013 \001(\005\""
    "a\n\010MetaData\022\017\n\007ms_path\030\001 \002(\t\022\021\n\tfile_has"
    "h\030\002 \002(\t\022\r\n\005stats\030\003 \001(\t\022\021\n\tfile_size\030\004 \001("
    "\005\022\017\n\007outname\030\005 \001(\t\"[\n\005Chunk\022\030\n\020compressi"
    "on_type\030\001 \001(\t\022\020\n\010chunklet\030\002 \003(\t\022&\n\036pre_c"
    "ompression_chunklet_size_\030\003 \003(\005\"k\n\013Share"
    "FromMe\022\020\n\010share_id\030\001 \002(\005\022\022\n\nshare_name\030\002"
    " \002(\t\022\r\n\005owner\030\003 \001(\t\022\030\n\020meta_data_map_id\030"
    "\004 \003(\005\022\r\n\005users\030\005 \003(\t\"\205\001\n\tShareToMe\022\020\n\010sh"
    "are_id\030\001 \002(\005\022\022\n\nshare_name\030\002 \002(\t\022\r\n\005owne"
    "r\030\003 \002(\t\022#\n\004mdms\030\004 \003(\0132\025.maidsafe.MetaDat"
    "aMap\022\036\n\003dms\030\005 \003(\0132\021.maidsafe.DataMap\"\270\001\n"
    "\026ShareToMeBufferMessage\022\020\n\010share_id\030\001 \002("
    "\005\022\022\n\nshare_name\030\002 \001(\t\022\r\n\005owner\030\003 \002(\t\022$\n\002"
    "op\030\004 \002(\0162\030.maidsafe.ShareOperation\022#\n\004md"
    "ms\030\005 \003(\0132\025.maidsafe.MetaDataMap\022\036\n\003dms\030\006"
    " \003(\0132\021.maidsafe.DataMap\"\335\001\n\tDataAtlas\022\023\n"
    "\013root_db_key\030\001 \001(\t\022\033\n\004keys\030\002 \003(\0132\r.maids"
    "afe.Key\022#\n\004mdms\030\003 \003(\0132\025.maidsafe.MetaDat"
    "aMap\022\036\n\003dms\030\004 \003(\0132\021.maidsafe.DataMap\022,\n\r"
    "offered_share\030\005 \003(\0132\025.maidsafe.ShareFrom"
    "Me\022+\n\016accepted_share\030\006 \003(\0132\023.maidsafe.Sh"
    "areToMe*\240\001\n\010itemtype\022\020\n\014REGULAR_FILE\020\000\022\016"
    "\n\nSMALL_FILE\020\001\022\016\n\nEMPTY_FILE\020\002\022\017\n\013LOCKED"
    "_FILE\020\003\022\r\n\tDIRECTORY\020\004\022\023\n\017EMPTY_DIRECTOR"
    "Y\020\005\022\010\n\004LINK\020\006\022\026\n\022NOT_FOR_PROCESSING\020\007\022\013\n"
    "\007UNKNOWN\020\010*Y\n\016ShareOperation\022\r\n\tSHARE_AD"
    "D\020\000\022\020\n\014SHARE_REMOVE\020\001\022\022\n\016SHARE_ADD_ITEM\020"
    "\002\022\022\n\016SHARE_DEL_ITEM\020\003*Y\n\nPacketType\022\t\n\005A"
    "NMID\020\000\022\n\n\006ANTMID\020\001\022\n\n\006ANSMID\020\002\022\010\n\004MAID\020\003"
    "\022\010\n\004PMID\020\004\022\n\n\006ANMPID\020\005\022\010\n\004MPID\020\006", 1712,
  &protobuf_BuildDesc_datamaps_2eproto_AssignGlobalDescriptors);
}

// Force BuildDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_datamaps_2eproto {
  StaticDescriptorInitializer_datamaps_2eproto() {
    protobuf_BuildDesc_datamaps_2eproto();
  }
} static_descriptor_initializer_datamaps_2eproto_;

const ::google::protobuf::EnumDescriptor* itemtype_descriptor() {
  if (itemtype_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return itemtype_descriptor_;
}
bool itemtype_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
      return true;
    default:
      return false;
  }
}

const ::google::protobuf::EnumDescriptor* ShareOperation_descriptor() {
  if (ShareOperation_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareOperation_descriptor_;
}
bool ShareOperation_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
    case 2:
    case 3:
      return true;
    default:
      return false;
  }
}

const ::google::protobuf::EnumDescriptor* PacketType_descriptor() {
  if (PacketType_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return PacketType_descriptor_;
}
bool PacketType_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
      return true;
    default:
      return false;
  }
}


// ===================================================================

const ::std::string Key::_default_id_;

const ::std::string Key::_default_private_key_;
const ::std::string Key::_default_public_key_;
Key::Key()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    id_(const_cast< ::std::string*>(&_default_id_)),
    type_(0),
    private_key_(const_cast< ::std::string*>(&_default_private_key_)),
    public_key_(const_cast< ::std::string*>(&_default_public_key_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void Key::InitAsDefaultInstance() {}

Key::Key(const Key& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    id_(const_cast< ::std::string*>(&_default_id_)),
    type_(0),
    private_key_(const_cast< ::std::string*>(&_default_private_key_)),
    public_key_(const_cast< ::std::string*>(&_default_public_key_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

Key::~Key() {
  if (id_ != &_default_id_) {
    delete id_;
  }
  if (private_key_ != &_default_private_key_) {
    delete private_key_;
  }
  if (public_key_ != &_default_public_key_) {
    delete public_key_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* Key::descriptor() {
  if (Key_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return Key_descriptor_;
}

const Key& Key::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

Key* Key::default_instance_ = NULL;

Key* Key::New() const {
  return new Key;
}

const ::google::protobuf::Descriptor* Key::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* Key::GetReflection() const {
  if (Key_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return Key_reflection_;
}

// ===================================================================

const ::std::string DataMap::_default_file_hash_;
const ::std::string DataMap::_default_se_version_;




DataMap::DataMap()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    file_hash_(const_cast< ::std::string*>(&_default_file_hash_)),
    se_version_(const_cast< ::std::string*>(&_default_se_version_)),
    compression_on_(false) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void DataMap::InitAsDefaultInstance() {}

DataMap::DataMap(const DataMap& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    file_hash_(const_cast< ::std::string*>(&_default_file_hash_)),
    se_version_(const_cast< ::std::string*>(&_default_se_version_)),
    compression_on_(false) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

DataMap::~DataMap() {
  if (file_hash_ != &_default_file_hash_) {
    delete file_hash_;
  }
  if (se_version_ != &_default_se_version_) {
    delete se_version_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* DataMap::descriptor() {
  if (DataMap_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return DataMap_descriptor_;
}

const DataMap& DataMap::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

DataMap* DataMap::default_instance_ = NULL;

DataMap* DataMap::New() const {
  return new DataMap;
}

const ::google::protobuf::Descriptor* DataMap::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* DataMap::GetReflection() const {
  if (DataMap_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return DataMap_reflection_;
}

// ===================================================================


const ::std::string MetaDataMap::_default_display_name_;


const ::std::string MetaDataMap::_default_stats_;
const ::std::string MetaDataMap::_default_tag_;





MetaDataMap::MetaDataMap()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    id_(0),
    display_name_(const_cast< ::std::string*>(&_default_display_name_)),
    type_(0),
    stats_(const_cast< ::std::string*>(&_default_stats_)),
    tag_(const_cast< ::std::string*>(&_default_tag_)),
    file_size_high_(0),
    file_size_low_(0),
    creation_time_(0),
    last_modified_(0),
    last_access_(0) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void MetaDataMap::InitAsDefaultInstance() {}

MetaDataMap::MetaDataMap(const MetaDataMap& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    id_(0),
    display_name_(const_cast< ::std::string*>(&_default_display_name_)),
    type_(0),
    stats_(const_cast< ::std::string*>(&_default_stats_)),
    tag_(const_cast< ::std::string*>(&_default_tag_)),
    file_size_high_(0),
    file_size_low_(0),
    creation_time_(0),
    last_modified_(0),
    last_access_(0) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

MetaDataMap::~MetaDataMap() {
  if (display_name_ != &_default_display_name_) {
    delete display_name_;
  }
  if (stats_ != &_default_stats_) {
    delete stats_;
  }
  if (tag_ != &_default_tag_) {
    delete tag_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* MetaDataMap::descriptor() {
  if (MetaDataMap_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return MetaDataMap_descriptor_;
}

const MetaDataMap& MetaDataMap::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

MetaDataMap* MetaDataMap::default_instance_ = NULL;

MetaDataMap* MetaDataMap::New() const {
  return new MetaDataMap;
}

const ::google::protobuf::Descriptor* MetaDataMap::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* MetaDataMap::GetReflection() const {
  if (MetaDataMap_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return MetaDataMap_reflection_;
}

// ===================================================================

const ::std::string MetaData::_default_ms_path_;
const ::std::string MetaData::_default_file_hash_;
const ::std::string MetaData::_default_stats_;

const ::std::string MetaData::_default_outname_;
MetaData::MetaData()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    ms_path_(const_cast< ::std::string*>(&_default_ms_path_)),
    file_hash_(const_cast< ::std::string*>(&_default_file_hash_)),
    stats_(const_cast< ::std::string*>(&_default_stats_)),
    file_size_(0),
    outname_(const_cast< ::std::string*>(&_default_outname_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void MetaData::InitAsDefaultInstance() {}

MetaData::MetaData(const MetaData& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    ms_path_(const_cast< ::std::string*>(&_default_ms_path_)),
    file_hash_(const_cast< ::std::string*>(&_default_file_hash_)),
    stats_(const_cast< ::std::string*>(&_default_stats_)),
    file_size_(0),
    outname_(const_cast< ::std::string*>(&_default_outname_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

MetaData::~MetaData() {
  if (ms_path_ != &_default_ms_path_) {
    delete ms_path_;
  }
  if (file_hash_ != &_default_file_hash_) {
    delete file_hash_;
  }
  if (stats_ != &_default_stats_) {
    delete stats_;
  }
  if (outname_ != &_default_outname_) {
    delete outname_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* MetaData::descriptor() {
  if (MetaData_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return MetaData_descriptor_;
}

const MetaData& MetaData::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

MetaData* MetaData::default_instance_ = NULL;

MetaData* MetaData::New() const {
  return new MetaData;
}

const ::google::protobuf::Descriptor* MetaData::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* MetaData::GetReflection() const {
  if (MetaData_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return MetaData_reflection_;
}

// ===================================================================

const ::std::string Chunk::_default_compression_type_;


Chunk::Chunk()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    compression_type_(const_cast< ::std::string*>(&_default_compression_type_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void Chunk::InitAsDefaultInstance() {}

Chunk::Chunk(const Chunk& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    compression_type_(const_cast< ::std::string*>(&_default_compression_type_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

Chunk::~Chunk() {
  if (compression_type_ != &_default_compression_type_) {
    delete compression_type_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* Chunk::descriptor() {
  if (Chunk_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return Chunk_descriptor_;
}

const Chunk& Chunk::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

Chunk* Chunk::default_instance_ = NULL;

Chunk* Chunk::New() const {
  return new Chunk;
}

const ::google::protobuf::Descriptor* Chunk::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* Chunk::GetReflection() const {
  if (Chunk_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return Chunk_reflection_;
}

// ===================================================================


const ::std::string ShareFromMe::_default_share_name_;
const ::std::string ShareFromMe::_default_owner_;


ShareFromMe::ShareFromMe()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    share_id_(0),
    share_name_(const_cast< ::std::string*>(&_default_share_name_)),
    owner_(const_cast< ::std::string*>(&_default_owner_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void ShareFromMe::InitAsDefaultInstance() {}

ShareFromMe::ShareFromMe(const ShareFromMe& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    share_id_(0),
    share_name_(const_cast< ::std::string*>(&_default_share_name_)),
    owner_(const_cast< ::std::string*>(&_default_owner_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

ShareFromMe::~ShareFromMe() {
  if (share_name_ != &_default_share_name_) {
    delete share_name_;
  }
  if (owner_ != &_default_owner_) {
    delete owner_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* ShareFromMe::descriptor() {
  if (ShareFromMe_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareFromMe_descriptor_;
}

const ShareFromMe& ShareFromMe::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

ShareFromMe* ShareFromMe::default_instance_ = NULL;

ShareFromMe* ShareFromMe::New() const {
  return new ShareFromMe;
}

const ::google::protobuf::Descriptor* ShareFromMe::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* ShareFromMe::GetReflection() const {
  if (ShareFromMe_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareFromMe_reflection_;
}

// ===================================================================


const ::std::string ShareToMe::_default_share_name_;
const ::std::string ShareToMe::_default_owner_;


ShareToMe::ShareToMe()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    share_id_(0),
    share_name_(const_cast< ::std::string*>(&_default_share_name_)),
    owner_(const_cast< ::std::string*>(&_default_owner_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void ShareToMe::InitAsDefaultInstance() {}

ShareToMe::ShareToMe(const ShareToMe& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    share_id_(0),
    share_name_(const_cast< ::std::string*>(&_default_share_name_)),
    owner_(const_cast< ::std::string*>(&_default_owner_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

ShareToMe::~ShareToMe() {
  if (share_name_ != &_default_share_name_) {
    delete share_name_;
  }
  if (owner_ != &_default_owner_) {
    delete owner_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* ShareToMe::descriptor() {
  if (ShareToMe_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareToMe_descriptor_;
}

const ShareToMe& ShareToMe::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

ShareToMe* ShareToMe::default_instance_ = NULL;

ShareToMe* ShareToMe::New() const {
  return new ShareToMe;
}

const ::google::protobuf::Descriptor* ShareToMe::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* ShareToMe::GetReflection() const {
  if (ShareToMe_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareToMe_reflection_;
}

// ===================================================================


const ::std::string ShareToMeBufferMessage::_default_share_name_;
const ::std::string ShareToMeBufferMessage::_default_owner_;



ShareToMeBufferMessage::ShareToMeBufferMessage()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    share_id_(0),
    share_name_(const_cast< ::std::string*>(&_default_share_name_)),
    owner_(const_cast< ::std::string*>(&_default_owner_)),
    op_(0) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void ShareToMeBufferMessage::InitAsDefaultInstance() {}

ShareToMeBufferMessage::ShareToMeBufferMessage(const ShareToMeBufferMessage& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    share_id_(0),
    share_name_(const_cast< ::std::string*>(&_default_share_name_)),
    owner_(const_cast< ::std::string*>(&_default_owner_)),
    op_(0) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

ShareToMeBufferMessage::~ShareToMeBufferMessage() {
  if (share_name_ != &_default_share_name_) {
    delete share_name_;
  }
  if (owner_ != &_default_owner_) {
    delete owner_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* ShareToMeBufferMessage::descriptor() {
  if (ShareToMeBufferMessage_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareToMeBufferMessage_descriptor_;
}

const ShareToMeBufferMessage& ShareToMeBufferMessage::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

ShareToMeBufferMessage* ShareToMeBufferMessage::default_instance_ = NULL;

ShareToMeBufferMessage* ShareToMeBufferMessage::New() const {
  return new ShareToMeBufferMessage;
}

const ::google::protobuf::Descriptor* ShareToMeBufferMessage::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* ShareToMeBufferMessage::GetReflection() const {
  if (ShareToMeBufferMessage_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return ShareToMeBufferMessage_reflection_;
}

// ===================================================================

const ::std::string DataAtlas::_default_root_db_key_;





DataAtlas::DataAtlas()
  : ::google::protobuf::Message(),
    _cached_size_(0),
    root_db_key_(const_cast< ::std::string*>(&_default_root_db_key_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

void DataAtlas::InitAsDefaultInstance() {}

DataAtlas::DataAtlas(const DataAtlas& from)
  : ::google::protobuf::Message(),
    _cached_size_(0),
    root_db_key_(const_cast< ::std::string*>(&_default_root_db_key_)) {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  MergeFrom(from);
}

DataAtlas::~DataAtlas() {
  if (root_db_key_ != &_default_root_db_key_) {
    delete root_db_key_;
  }
  if (this != default_instance_) {
  }
}

const ::google::protobuf::Descriptor* DataAtlas::descriptor() {
  if (DataAtlas_descriptor_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return DataAtlas_descriptor_;
}

const DataAtlas& DataAtlas::default_instance() {
  if (default_instance_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return *default_instance_;
}

DataAtlas* DataAtlas::default_instance_ = NULL;

DataAtlas* DataAtlas::New() const {
  return new DataAtlas;
}

const ::google::protobuf::Descriptor* DataAtlas::GetDescriptor() const {
  return descriptor();
}

const ::google::protobuf::Reflection* DataAtlas::GetReflection() const {
  if (DataAtlas_reflection_ == NULL) protobuf_BuildDesc_datamaps_2eproto();
  return DataAtlas_reflection_;
}

}  // namespace maidsafe
