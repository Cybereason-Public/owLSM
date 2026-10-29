```diff
diff --git a/src/Userspace/async_event_work/shell_async_worker.cpp b/src/Userspace/async_event_work/shell_async_worker.cpp
index 4af450f..39052b8 100644
--- a/src/Userspace/async_event_work/shell_async_worker.cpp
+++ b/src/Userspace/async_event_work/shell_async_worker.cpp
@@ -6,6 +6,9 @@
 #include "probes_objects/uprobe_probe.hpp"
 #include "shell_detection/shell_binary_info_extractor.hpp"
 
+#include <string>
+#include <string_view>
+
 namespace owlsm::events
 {
 
@@ -23,20 +26,22 @@ void ShellAsyncWorker::distributeIfNeeded(std::shared_ptr<Event> event)
         return;
     }
 
-    if (ShellBinaryInfoExtractor::getShellType(event->process.file.path.value) == ShellType::UNKNOWN)
+    const std::string path(std::string_view(event->process.file.path.value));
+    if (ShellBinaryInfoExtractor::getShellType(path) == ShellType::UNKNOWN)
     {
         m_non_shells_quick_cache.insert(key);
         return;
     }
 
     rememberKnownShell(key);
+    event->process.file.path.value = path;
     enqueue(std::move(event));
 }
 
 void ShellAsyncWorker::processItem(std::shared_ptr<Event>& item)
 {
     const FileKey key = fileKeyFromEvent(*item);
-    const std::string& shell_path = item->process.file.path.value;
+    const std::string shell_path(std::string_view(item->process.file.path.value));
 
     const auto shell_info = ShellBinaryInfoExtractor::getShellInfo(shell_path);
     if (!shell_info.has_value())
diff --git a/src/Userspace/events/event.hpp b/src/Userspace/events/event.hpp
index 648a9fb..1a484e7 100644
--- a/src/Userspace/events/event.hpp
+++ b/src/Userspace/events/event.hpp
@@ -5,14 +5,125 @@
 
 #include <cstring>
 #include <map>
+#include <string>
+#include <string_view>
+#include <utility>
 #include <variant>
 
 namespace owlsm::events
 {
 
+class EventString
+{
+public:
+    EventString() = default;
+    EventString(const char* data, short length);
+    EventString(const EventString& other);
+    EventString(EventString&& other) noexcept;
+    EventString& operator=(const EventString& other);
+    EventString& operator=(EventString&& other) noexcept;
+    EventString& operator=(std::string_view text);
+    operator std::string_view() const;
+    const char* data() const;
+    std::size_t size() const;
+    bool empty() const;
+
+private:
+    void copyFrom(const EventString& other);
+    void moveFrom(EventString&& other);
+
+    std::string m_owned;
+    std::string_view m_view;
+};
+
+inline EventString::EventString(const char* data, short length)
+    : m_view(data != nullptr ? data : "", static_cast<std::size_t>(length < 0 ? 0 : length))
+{
+}
+
+inline EventString::EventString(const EventString& other)
+{
+    copyFrom(other);
+}
+
+inline EventString::EventString(EventString&& other) noexcept
+{
+    moveFrom(std::move(other));
+}
+
+inline EventString& EventString::operator=(const EventString& other)
+{
+    if (this != &other)
+    {
+        copyFrom(other);
+    }
+    return *this;
+}
+
+inline EventString& EventString::operator=(EventString&& other) noexcept
+{
+    if (this != &other)
+    {
+        moveFrom(std::move(other));
+    }
+    return *this;
+}
+
+inline EventString& EventString::operator=(std::string_view text)
+{
+    m_owned.assign(text);
+    m_view = m_owned;
+    return *this;
+}
+
+inline EventString::operator std::string_view() const
+{
+    return m_view;
+}
+
+inline const char* EventString::data() const
+{
+    return m_view.data();
+}
+
+inline std::size_t EventString::size() const
+{
+    return m_view.size();
+}
+
+inline bool EventString::empty() const
+{
+    return m_view.empty();
+}
+
+inline void EventString::copyFrom(const EventString& other)
+{
+    if (!other.m_owned.empty())
+    {
+        m_owned = other.m_owned;
+        m_view = m_owned;
+        return;
+    }
+    m_owned.clear();
+    m_view = other.m_view;
+}
+
+inline void EventString::moveFrom(EventString&& other)
+{
+    if (!other.m_owned.empty())
+    {
+        m_owned = std::move(other.m_owned);
+        m_view = m_owned;
+        other.m_view = other.m_owned;
+        return;
+    }
+    m_owned.clear();
+    m_view = other.m_view;
+}
+
 struct Path
 {
-    std::string value;
+    EventString value;
 
     Path() = default;
     explicit Path(const path_t& p) : value(p.value, p.length) {}
@@ -20,7 +131,7 @@ struct Path
 
 struct CommandLine
 {
-    std::string value;
+    EventString value;
 
     CommandLine() = default;
     explicit CommandLine(const command_line_t& c) : value(c.value, c.length) {}
@@ -28,7 +139,7 @@ struct CommandLine
 
 struct Filename
 {
-    std::string value;
+    EventString value;
 
     Filename() = default;
     explicit Filename(const filename_t& f) : value(f.value, f.length) {}
diff --git a/src/Userspace/events/event_to_flatbuffer.cpp b/src/Userspace/events/event_to_flatbuffer.cpp
index 542bfd8..a4a7c51 100644
--- a/src/Userspace/events/event_to_flatbuffer.cpp
+++ b/src/Userspace/events/event_to_flatbuffer.cpp
@@ -3,6 +3,7 @@
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <cstring>
+#include <string_view>
 
 namespace owlsm::events
 {
@@ -143,8 +144,8 @@ template <typename MessageType>
 flatbuffers::Offset<fb::File> EventToFlatbuffer<MessageType>::serializeFile(
     flatbuffers::FlatBufferBuilder& builder, const File& f)
 {
-    auto path_off = builder.CreateString(f.path.value);
-    auto filename_off = builder.CreateString(f.filename.value);
+    auto path_off = builder.CreateString(std::string_view(f.path.value));
+    auto filename_off = builder.CreateString(std::string_view(f.filename.value));
     fb::Owner owner(f.owner.uid, f.owner.gid);
 
     return fb::CreateFile(
@@ -158,8 +159,8 @@ flatbuffers::Offset<fb::Process> EventToFlatbuffer<MessageType>::serializeProces
     flatbuffers::FlatBufferBuilder& builder, const Process& p)
 {
     auto file_off = serializeFile(builder, p.file);
-    auto cmd_off = builder.CreateString(p.cmd.value);
-    auto shell_cmd_off = builder.CreateString(p.shell_command.value);
+    auto cmd_off = builder.CreateString(std::string_view(p.cmd.value));
+    auto shell_cmd_off = builder.CreateString(std::string_view(p.shell_command.value));
 
     fb::StdioFileDescriptors stdio(
         toFbFileType(p.stdio_file_descriptors_at_process_creation.stdin_fd),
diff --git a/src/Userspace/events/event_to_json.cpp b/src/Userspace/events/event_to_json.cpp
index d05f4ba..21282f6 100644
--- a/src/Userspace/events/event_to_json.cpp
+++ b/src/Userspace/events/event_to_json.cpp
@@ -647,7 +647,7 @@ private:
 
     template <typename Enum>
     bool setEnum(yyjson_mut_val* slot, Enum value) const;
-    void setString(yyjson_mut_val* slot, const std::string& value) const;
+    void setString(yyjson_mut_val* slot, std::string_view value) const;
     void setUint(yyjson_mut_val* slot, uint64_t value) const;
     void setSint(yyjson_mut_val* slot, int64_t value) const;
     void setAddress(char* buffer, yyjson_mut_val* slot, int family, const void* address) const;
@@ -989,7 +989,7 @@ bool EventJsonWriter::Shapes::setEnum(yyjson_mut_val* slot, Enum value) const
     return yyjson_mut_set_strn(slot, name.data(), name.size());
 }
 
-void EventJsonWriter::Shapes::setString(yyjson_mut_val* slot, const std::string& value) const
+void EventJsonWriter::Shapes::setString(yyjson_mut_val* slot, std::string_view value) const
 {
     yyjson_mut_set_strn(slot, value.data(), value.size());
 }
```
