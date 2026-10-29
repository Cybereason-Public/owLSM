```diff
diff --git a/src/Userspace/ringbuffers_messages_handlers.hpp b/src/Userspace/ringbuffers_messages_handlers.hpp
index 31fb2f2..a0c71ba 100644
--- a/src/Userspace/ringbuffers_messages_handlers.hpp
+++ b/src/Userspace/ringbuffers_messages_handlers.hpp
@@ -23,6 +23,7 @@
 #include <string>
 #include <chrono>
 #include <algorithm>
+#include <utility>
 #include <unistd.h>
 
 namespace owlsm
@@ -151,22 +152,49 @@ private:
         {
             std::lock_guard<std::mutex> lock(m_main_queue_mutex);
             static const auto max_size = static_cast<std::size_t>(owlsm::globals::g_config.userspace.max_events_queue_size);
-            const std::size_t room = m_main_queue.size() >= max_size ? 0 : max_size - m_main_queue.size();
+            const std::size_t room = m_main_queue_events >= max_size ? 0 : max_size - m_main_queue_events;
             const std::size_t accepted = std::min(room, m_local_queue.size());
-            for (std::size_t index = 0; index < accepted; ++index)
+            if (accepted == m_local_queue.size())
             {
-                m_main_queue.push_back(m_local_queue[index]);
+                m_main_queue.push_back(std::move(m_local_queue));
+                m_main_queue_events += accepted;
+                enqueued = true;
+                if (!m_spare_batches.empty())
+                {
+                    m_local_queue = std::move(m_spare_batches.back());
+                    m_spare_batches.pop_back();
+                }
+            }
+            else if (accepted > 0)
+            {
+                std::vector<RawType> partial;
+                partial.reserve(accepted);
+                for (std::size_t index = 0; index < accepted; ++index)
+                {
+                    partial.push_back(m_local_queue[index]);
+                }
+                m_main_queue.push_back(std::move(partial));
+                m_main_queue_events += accepted;
+                dropped = m_local_queue.size() - accepted;
+                enqueued = true;
+            }
+            else
+            {
+                dropped = m_local_queue.size();
             }
-            dropped = m_local_queue.size() - accepted;
-            enqueued = accepted > 0;
         }
-        m_local_queue.clear();
 
         if (enqueued)
         {
             m_main_queue_cv.notify_one();
         }
 
+        m_local_queue.clear();
+        if (m_local_queue.capacity() < LOCAL_QUEUE_MAX_SIZE)
+        {
+            m_local_queue.reserve(LOCAL_QUEUE_MAX_SIZE);
+        }
+
         if (dropped == 0)
         {
             return true;
@@ -205,7 +233,8 @@ private:
                 }
                 else
                 {
-                    m_thread_queue.swap(m_main_queue);
+                    m_thread_batches.swap(m_main_queue);
+                    m_main_queue_events = 0;
                 }
             }
 
@@ -216,7 +245,7 @@ private:
             writeAndRecord(serializer->data(), serializer->size());
             distributeMessages();
             m_messages_queue.clear();
-            m_thread_queue.clear();
+            recycleBatches();
         }
 
         while (!m_poll_thread_done.load(std::memory_order_acquire))
@@ -226,10 +255,11 @@ private:
 
         {
             std::lock_guard<std::mutex> lock(m_main_queue_mutex);
-            m_thread_queue.swap(m_main_queue);
+            m_thread_batches.swap(m_main_queue);
+            m_main_queue_events = 0;
         }
 
-        if (!m_thread_queue.empty())
+        if (!m_thread_batches.empty())
         {
             convertToMessages();
             enrichMessages();
@@ -237,19 +267,43 @@ private:
             writeAndRecord(serializer->data(), serializer->size());
             distributeMessages();
             m_messages_queue.clear();
-            m_thread_queue.clear();
+            recycleBatches();
         }
     }
 
     void convertToMessages()
     {
-        m_messages_queue.resize(m_thread_queue.size());
-        std::transform(
-            m_thread_queue.begin(),
-            m_thread_queue.end(),
-            m_messages_queue.begin(),
-            [](const RawType& ev) { return std::make_shared<MessageType>(ev); }
-        );
+        std::size_t count = 0;
+        for (const auto& batch : m_thread_batches)
+        {
+            count += batch.size();
+        }
+        m_messages_queue.resize(count);
+        auto output = m_messages_queue.begin();
+        for (const auto& batch : m_thread_batches)
+        {
+            output = std::transform(
+                batch.begin(),
+                batch.end(),
+                output,
+                [](const RawType& ev) { return std::make_shared<MessageType>(ev); }
+            );
+        }
+    }
+
+    void recycleBatches()
+    {
+        std::lock_guard<std::mutex> lock(m_main_queue_mutex);
+        for (auto& batch : m_thread_batches)
+        {
+            if (m_spare_batches.size() >= SPARE_BATCH_LIMIT || batch.capacity() < LOCAL_QUEUE_MAX_SIZE)
+            {
+                continue;
+            }
+            batch.clear();
+            m_spare_batches.push_back(std::move(batch));
+        }
+        m_thread_batches.clear();
     }
 
     void enrichMessages()
@@ -311,12 +365,15 @@ private:
     std::thread m_polling_thread;
     std::thread m_processing_thread;
     static constexpr std::size_t LOCAL_QUEUE_MAX_SIZE = 100;
+    static constexpr std::size_t SPARE_BATCH_LIMIT = 2;
     static constexpr std::chrono::microseconds WAIT_TIME{250};
     std::vector<RawType> m_local_queue;
-    std::deque<RawType> m_main_queue;
+    std::deque<std::vector<RawType>> m_main_queue;
+    std::vector<std::vector<RawType>> m_spare_batches;
+    std::size_t m_main_queue_events = 0;
     std::mutex m_main_queue_mutex;
     std::condition_variable m_main_queue_cv;
-    std::deque<RawType> m_thread_queue;
+    std::deque<std::vector<RawType>> m_thread_batches;
     std::vector<std::shared_ptr<MessageType>> m_messages_queue;
     SyncEnrichment m_sync_enrichment;
     AsyncWorkDistributor m_async_work_distributor;
```
