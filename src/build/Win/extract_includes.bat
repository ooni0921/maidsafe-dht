md include\maidsafe
for /f %%G in ('dir /b "..\..\maidsafe\*.h"') do (copy ..\..\maidsafe\%%G include\maidsafe\%%G)
copy ..\..\protobuf\signed_kadvalue.pb.h include\maidsafe\signed_kadvalue.pb.h
copy ..\..\protobuf\kademlia_service_messages.pb.h include\maidsafe\kademlia_service_messages.pb.h
copy ..\..\protobuf\contact_info.pb.h include\maidsafe\contact_info.pb.h
copy ..\..\protobuf\general_messages.pb.h include\maidsafe\general_messages.pb.h
