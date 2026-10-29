```diff
diff --git a/src/Userspace/async_event_work/shell_async_worker.cpp b/src/Userspace/async_event_work/shell_async_worker.cpp
index 4af450f..195991e 100644
--- a/src/Userspace/async_event_work/shell_async_worker.cpp
+++ b/src/Userspace/async_event_work/shell_async_worker.cpp
@@ -23,7 +23,8 @@ void ShellAsyncWorker::distributeIfNeeded(std::shared_ptr<Event> event)
         return;
     }
 
-    if (ShellBinaryInfoExtractor::getShellType(event->process.file.path.value) == ShellType::UNKNOWN)
+    const std::string path(event->process.file.path.value.data(), event->process.file.path.value.size());
+    if (ShellBinaryInfoExtractor::getShellType(path) == ShellType::UNKNOWN)
     {
         m_non_shells_quick_cache.insert(key);
         return;
@@ -36,7 +37,7 @@ void ShellAsyncWorker::distributeIfNeeded(std::shared_ptr<Event> event)
 void ShellAsyncWorker::processItem(std::shared_ptr<Event>& item)
 {
     const FileKey key = fileKeyFromEvent(*item);
-    const std::string& shell_path = item->process.file.path.value;
+    const std::string shell_path(item->process.file.path.value.data(), item->process.file.path.value.size());
 
     const auto shell_info = ShellBinaryInfoExtractor::getShellInfo(shell_path);
     if (!shell_info.has_value())
diff --git a/src/Userspace/events/event.hpp b/src/Userspace/events/event.hpp
index 648a9fb..5e5b0e2 100644
--- a/src/Userspace/events/event.hpp
+++ b/src/Userspace/events/event.hpp
@@ -3,35 +3,87 @@
 #include "events_structs.h"
 #include "configuration/rule.hpp"
 
+#include <cstddef>
 #include <cstring>
 #include <map>
+#include <string>
+#include <string_view>
 #include <variant>
 
 namespace owlsm::events
 {
 
+template <size_t MaxLen>
+struct InlineString
+{
+    char buf[MaxLen]{};
+    short length = 0;
+
+    InlineString() = default;
+
+    void assign(const char* s, short len)
+    {
+        if (s == nullptr || len <= 0)
+        {
+            length = 0;
+            buf[0] = '\0';
+            return;
+        }
+        const short max_len = static_cast<short>(MaxLen - 1);
+        length = len > max_len ? max_len : len;
+        std::memcpy(buf, s, static_cast<size_t>(length));
+        buf[length] = '\0';
+    }
+
+    InlineString& operator=(const std::string& s)
+    {
+        assign(s.data(), static_cast<short>(s.size()));
+        return *this;
+    }
+
+    InlineString& operator=(const char* s)
+    {
+        assign(s, s ? static_cast<short>(std::strlen(s)) : 0);
+        return *this;
+    }
+
+    const char* data() const { return buf; }
+    const char* c_str() const { return buf; }
+    size_t size() const { return static_cast<size_t>(length); }
+    operator std::string_view() const { return {buf, static_cast<size_t>(length)}; }
+};
+
 struct Path
 {
-    std::string value;
+    InlineString<PATH_MAX> value;
 
     Path() = default;
-    explicit Path(const path_t& p) : value(p.value, p.length) {}
+    explicit Path(const path_t& p)
+    {
+        value.assign(p.value, p.length);
+    }
 };
 
 struct CommandLine
 {
-    std::string value;
+    InlineString<CMD_MAX> value;
 
     CommandLine() = default;
-    explicit CommandLine(const command_line_t& c) : value(c.value, c.length) {}
+    explicit CommandLine(const command_line_t& c)
+    {
+        value.assign(c.value, c.length);
+    }
 };
 
 struct Filename
 {
-    std::string value;
+    InlineString<FILENAME_MAX_LENGTH> value;
 
     Filename() = default;
-    explicit Filename(const filename_t& f) : value(f.value, f.length) {}
+    explicit Filename(const filename_t& f)
+    {
+        value.assign(f.value, f.length);
+    }
 };
 
 struct Owner
diff --git a/src/Userspace/events/event_to_flatbuffer.cpp b/src/Userspace/events/event_to_flatbuffer.cpp
index 542bfd8..122c43d 100644
--- a/src/Userspace/events/event_to_flatbuffer.cpp
+++ b/src/Userspace/events/event_to_flatbuffer.cpp
@@ -143,8 +143,8 @@ template <typename MessageType>
 flatbuffers::Offset<fb::File> EventToFlatbuffer<MessageType>::serializeFile(
     flatbuffers::FlatBufferBuilder& builder, const File& f)
 {
-    auto path_off = builder.CreateString(f.path.value);
-    auto filename_off = builder.CreateString(f.filename.value);
+    auto path_off = builder.CreateString(f.path.value.data(), f.path.value.size());
+    auto filename_off = builder.CreateString(f.filename.value.data(), f.filename.value.size());
     fb::Owner owner(f.owner.uid, f.owner.gid);
 
     return fb::CreateFile(
@@ -158,8 +158,8 @@ template <typename MessageType>
 flatbuffers::Offset<fb::Process> EventToFlatbuffer<MessageType>::serializeProcess(
     flatbuffers::FlatBufferBuilder& builder, const Process& p)
 {
     auto file_off = serializeFile(builder, p.file);
-    auto cmd_off = builder.CreateString(p.cmd.value);
-    auto shell_cmd_off = builder.CreateString(p.shell_command.value);
+    auto cmd_off = builder.CreateString(p.cmd.value.data(), p.cmd.value.size());
+    auto shell_cmd_off = builder.CreateString(p.shell_command.value.data(), p.shell_command.value.size());
 
     fb::StdioFileDescriptors stdio(
         toFbFileType(p.stdio_file_descriptors_at_process_creation.stdin_fd),
diff --git a/src/Userspace/events/event_to_json.cpp b/src/Userspace/events/event_to_json.cpp
index d05f4ba..5e2d2b6 100644
--- a/src/Userspace/events/event_to_json.cpp
+++ b/src/Userspace/events/event_to_json.cpp
@@ -647,6 +647,7 @@ private:
 
     template <typename Enum>
     bool setEnum(yyjson_mut_val* slot, Enum value) const;
+    void setString(yyjson_mut_val* slot, std::string_view value) const;
     void setString(yyjson_mut_val* slot, const std::string& value) const;
     void setUint(yyjson_mut_val* slot, uint64_t value) const;
     void setSint(yyjson_mut_val* slot, int64_t value) const;
@@ -989,11 +990,16 @@ bool EventJsonWriter::Shapes::setEnum(yyjson_mut_val* slot, Enum value) const
     return yyjson_mut_set_strn(slot, name.data(), name.size());
 }
 
-void EventJsonWriter::Shapes::setString(yyjson_mut_val* slot, const std::string& value) const
+void EventJsonWriter::Shapes::setString(yyjson_mut_val* slot, std::string_view value) const
 {
     yyjson_mut_set_strn(slot, value.data(), value.size());
 }
 
+void EventJsonWriter::Shapes::setString(yyjson_mut_val* slot, const std::string& value) const
+{
+    setString(slot, std::string_view(value));
+}
+
 void EventJsonWriter::Shapes::setUint(yyjson_mut_val* slot, uint64_t value) const
 {
     yyjson_mut_set_uint(slot, value);
```
