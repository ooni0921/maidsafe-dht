md include\maidsafe\base
copy ..\..\src\base\alternativestore.h include\maidsafe\base\alternativestore.h
copy ..\..\src\base\crypto.h include\maidsafe\base\crypto.h
copy ..\..\src\base\log.h include\maidsafe\base\log.h
copy ..\..\src\base\online.h include\maidsafe\base\online.h
copy ..\..\src\base\routingtable.h include\maidsafe\base\routingtable.h
copy ..\..\src\base\utils.h include\maidsafe\base\utils.h
copy ..\..\src\base\validationinterface.h include\maidsafe\base\validationinterface.h

md include\maidsafe\kademlia
copy ..\..\src\kademlia\contact.h include\maidsafe\kademlia\contact.h
copy ..\..\src\kademlia\kadid.h include\maidsafe\kademlia\kadid.h
copy ..\..\src\kademlia\knode-api.h include\maidsafe\kademlia\knode-api.h

copy ..\..\src\maidsafe\maidsafe-dht.h include\maidsafe\maidsafe-dht.h
copy ..\..\src\maidsafe\maidsafe-dht_config.h include\maidsafe\maidsafe-dht_config.h

md include\maidsafe\protobuf
copy ..\..\src\protobuf\signed_kadvalue.pb.h include\maidsafe\protobuf\signed_kadvalue.pb.h
copy ..\..\src\protobuf\kademlia_service_messages.pb.h include\maidsafe\protobuf\kademlia_service_messages.pb.h
copy ..\..\src\protobuf\contact_info.pb.h include\maidsafe\protobuf\contact_info.pb.h
copy ..\..\src\protobuf\general_messages.pb.h include\maidsafe\protobuf\general_messages.pb.h

md include\maidsafe\rpcprotocol
copy ..\..\src\rpcprotocol\channel-api.h include\maidsafe\rpcprotocol\channel-api.h
copy ..\..\src\rpcprotocol\channelmanager-api.h include\maidsafe\rpcprotocol\channelmanager-api.h

md include\maidsafe\transport
copy ..\..\src\transport\transport-api.h include\maidsafe\transport\transport-api.h
copy ..\..\src\transport\transporthandler-api.h include\maidsafe\transport\transporthandler-api.h
copy ..\..\src\transport\transportudt.h include\maidsafe\transport\transportudt.h
