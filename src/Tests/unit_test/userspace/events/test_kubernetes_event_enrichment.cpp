#include <gtest/gtest.h>
#include "events/event_to_json.hpp"
#include "events/kubernetes_event_enrichment.hpp"

#include <3rd_party/nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

class KubernetesEventEnrichmentTest : public ::testing::Test
{
protected:
    static nlohmann::json serializeToJson(const owlsm::events::Event& event)
    {
        owlsm::events::EventToJson<owlsm::events::Event> serializer;
        std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {std::make_shared<owlsm::events::Event>(event)};
        serializer.buildOutputBuffer(msgs);
        const auto line = std::string(static_cast<const char*>(serializer.data()), serializer.size());
        return nlohmann::json::parse(line);
    }

    static owlsm::events::Kubernetes build(
        const std::string& node_name,
        const unsigned long long container_id,
        const std::optional<std::string>& pod_uid,
        const std::optional<owlsm::kubernetes::PodInfo>& pod_info)
    {
        owlsm::events::Kubernetes kubernetes;
        buildInto(kubernetes, node_name, container_id, pod_uid, pod_info);
        return kubernetes;
    }

    static void buildInto(
        owlsm::events::Kubernetes& kubernetes,
        const std::string& node_name,
        const unsigned long long container_id,
        const std::optional<std::string>& pod_uid,
        const std::optional<owlsm::kubernetes::PodInfo>& pod_info)
    {
        owlsm::events::KubernetesEventEnrichment::build(kubernetes, node_name, container_id, pod_uid, pod_info);
    }

    static owlsm::kubernetes::PodInfo makePod()
    {
        owlsm::kubernetes::PodInfo info;
        info.uid = "uid-1";
        info.name = "nginx";
        info.ns = "default";
        info.labels.emplace("app", "nginx");
        return info;
    }
};

TEST_F(KubernetesEventEnrichmentTest, event_constructor_copies_process_t_container_id_onto_process)
{
    event_t raw{};
    raw.type = FORK;
    raw.process.container_id = 0xabc;

    const owlsm::events::Event event(raw);
    EXPECT_EQ(event.process.container_id, 0xabcu);
    EXPECT_FALSE(event.kubernetes.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, has_any_value_false_when_all_fields_empty)
{
    EXPECT_FALSE(owlsm::events::Kubernetes{}.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, has_any_value_true_when_host_event_or_any_field_set)
{
    owlsm::events::Kubernetes host_only;
    host_only.host_event = true;
    EXPECT_TRUE(host_only.hasAnyValue());

    owlsm::events::Kubernetes container_only;
    container_only.container_id = 1;
    EXPECT_TRUE(container_only.hasAnyValue());

    owlsm::events::Kubernetes node_only;
    node_only.node_name = "worker-1";
    EXPECT_TRUE(node_only.hasAnyValue());

    owlsm::events::Kubernetes labels_only;
    labels_only.pod_labels.emplace("app", "nginx");
    EXPECT_TRUE(labels_only.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, host_event_sets_flag_and_omits_container_id)
{
    const auto k8s = build("worker-1", 0, std::nullopt, std::nullopt);
    EXPECT_TRUE(k8s.host_event);
    EXPECT_EQ(k8s.node_name, "worker-1");
    EXPECT_EQ(k8s.container_id, 0u);
    EXPECT_TRUE(k8s.pod_uid.empty());
    EXPECT_TRUE(k8s.pod_namespace.empty());
    EXPECT_TRUE(k8s.pod_name.empty());
    EXPECT_TRUE(k8s.pod_labels.empty());
    EXPECT_TRUE(k8s.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, host_event_without_node_name_still_emits_flag)
{
    const auto k8s = build("", 0, std::nullopt, std::nullopt);
    EXPECT_TRUE(k8s.host_event);
    EXPECT_TRUE(k8s.node_name.empty());
    EXPECT_EQ(k8s.container_id, 0u);
    EXPECT_TRUE(k8s.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, container_without_pod_uid_keeps_container_id)
{
    const auto k8s = build("worker-1", 0xabc, std::nullopt, std::nullopt);
    EXPECT_FALSE(k8s.host_event);
    EXPECT_EQ(k8s.node_name, "worker-1");
    EXPECT_EQ(k8s.container_id, 0xabcu);
    EXPECT_TRUE(k8s.pod_uid.empty());
    EXPECT_TRUE(k8s.pod_name.empty());
    EXPECT_TRUE(k8s.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, pod_uid_without_pod_info_omits_name_namespace_labels)
{
    const auto k8s = build("worker-1", 0xabc, std::string{"uid-1"}, std::nullopt);
    EXPECT_EQ(k8s.pod_uid, "uid-1");
    EXPECT_TRUE(k8s.pod_namespace.empty());
    EXPECT_TRUE(k8s.pod_name.empty());
    EXPECT_TRUE(k8s.pod_labels.empty());
}

TEST_F(KubernetesEventEnrichmentTest, empty_pod_uid_string_skips_pod_info)
{
    const auto k8s = build("worker-1", 0xabc, std::string{""}, makePod());
    EXPECT_FALSE(k8s.host_event);
    EXPECT_EQ(k8s.container_id, 0xabcu);
    EXPECT_TRUE(k8s.pod_uid.empty());
    EXPECT_TRUE(k8s.pod_namespace.empty());
    EXPECT_TRUE(k8s.pod_name.empty());
    EXPECT_TRUE(k8s.pod_labels.empty());
}

TEST_F(KubernetesEventEnrichmentTest, empty_pod_info_fields_are_left_unset)
{
    owlsm::kubernetes::PodInfo empty_info;
    empty_info.uid = "uid-1";

    const auto k8s = build("worker-1", 0xabc, std::string{"uid-1"}, empty_info);
    EXPECT_EQ(k8s.pod_uid, "uid-1");
    EXPECT_TRUE(k8s.pod_namespace.empty());
    EXPECT_TRUE(k8s.pod_name.empty());
    EXPECT_TRUE(k8s.pod_labels.empty());
}

TEST_F(KubernetesEventEnrichmentTest, full_enrichment_sets_all_keys)
{
    const auto k8s = build("worker-1", 0xabc, std::string{"uid-1"}, makePod());
    EXPECT_FALSE(k8s.host_event);
    EXPECT_EQ(k8s.node_name, "worker-1");
    EXPECT_EQ(k8s.container_id, 0xabcu);
    EXPECT_EQ(k8s.pod_uid, "uid-1");
    EXPECT_EQ(k8s.pod_namespace, "default");
    EXPECT_EQ(k8s.pod_name, "nginx");
    EXPECT_EQ(k8s.pod_labels.at("app"), "nginx");
}

TEST_F(KubernetesEventEnrichmentTest, build_resets_existing_fields)
{
    owlsm::events::Kubernetes kubernetes;
    kubernetes.node_name = "old-node";
    kubernetes.container_id = 0xdead;
    kubernetes.pod_uid = "old-uid";
    kubernetes.pod_namespace = "old-ns";
    kubernetes.pod_name = "old-name";
    kubernetes.pod_labels.emplace("app", "old");
    kubernetes.host_event = false;

    buildInto(kubernetes, "worker-1", 0, std::nullopt, std::nullopt);

    EXPECT_TRUE(kubernetes.host_event);
    EXPECT_EQ(kubernetes.node_name, "worker-1");
    EXPECT_EQ(kubernetes.container_id, 0u);
    EXPECT_TRUE(kubernetes.pod_uid.empty());
    EXPECT_TRUE(kubernetes.pod_namespace.empty());
    EXPECT_TRUE(kubernetes.pod_name.empty());
    EXPECT_TRUE(kubernetes.pod_labels.empty());
}

TEST_F(KubernetesEventEnrichmentTest, enrich_reads_container_id_argument)
{
    owlsm::events::Kubernetes kubernetes;
    const owlsm::events::KubernetesEventEnrichment enricher;
    enricher.enrich(kubernetes, 0xabc);

    EXPECT_FALSE(kubernetes.host_event);
    EXPECT_EQ(kubernetes.container_id, 0xabcu);
    EXPECT_TRUE(kubernetes.node_name.empty());
    EXPECT_TRUE(kubernetes.pod_uid.empty());
    EXPECT_TRUE(kubernetes.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, enrich_with_zero_container_id_is_host_event)
{
    owlsm::events::Kubernetes kubernetes;
    kubernetes.pod_name = "stale";
    const owlsm::events::KubernetesEventEnrichment enricher;
    enricher.enrich(kubernetes, 0);

    EXPECT_TRUE(kubernetes.host_event);
    EXPECT_EQ(kubernetes.container_id, 0u);
    EXPECT_TRUE(kubernetes.pod_name.empty());
    EXPECT_TRUE(kubernetes.hasAnyValue());
}

TEST_F(KubernetesEventEnrichmentTest, json_omits_process_container_id_and_empty_k8s_keys)
{
    owlsm::events::Event event;
    event.id = 1;
    event.type = FORK;
    event.process.pid = 10;
    event.process.ns_pid = 1;
    event.process.container_id = 0xabc;
    event.parent_process.pid = 1;
    event.data = owlsm::events::ForkEventData{};
    event.kubernetes.node_name = "worker-1";
    event.kubernetes.container_id = 0xabc;
    event.kubernetes.host_event = false;

    const auto j = serializeToJson(event);
    EXPECT_FALSE(j.contains("container_id"));
    EXPECT_FALSE(j["process"].contains("container_id"));
    EXPECT_FALSE(j["parent_process"].contains("container_id"));
    EXPECT_EQ(j["process"]["ns_pid"], 1);
    EXPECT_EQ(j["process"]["ns_ppid"], 0);
    ASSERT_TRUE(j.contains("kubernetes"));
    EXPECT_EQ(j["kubernetes"]["node_name"], "worker-1");
    EXPECT_EQ(j["kubernetes"]["container_id"], 0xabc);
    EXPECT_EQ(j["kubernetes"]["host_event"], false);
    EXPECT_FALSE(j["kubernetes"].contains("pod_uid"));
    EXPECT_FALSE(j["kubernetes"].contains("pod_namespace"));
    EXPECT_FALSE(j["kubernetes"].contains("pod_name"));
    EXPECT_FALSE(j["kubernetes"].contains("pod_labels"));
}

TEST_F(KubernetesEventEnrichmentTest, json_omits_kubernetes_when_absent)
{
    owlsm::events::Event event;
    event.id = 2;
    event.type = FORK;
    event.data = owlsm::events::ForkEventData{};

    const auto j = serializeToJson(event);
    EXPECT_FALSE(j.contains("kubernetes"));
    EXPECT_FALSE(j.contains("container_id"));
}

TEST_F(KubernetesEventEnrichmentTest, json_emits_kubernetes_when_only_host_event)
{
    owlsm::events::Event event;
    event.id = 3;
    event.type = FORK;
    event.data = owlsm::events::ForkEventData{};
    event.kubernetes.host_event = true;

    const auto j = serializeToJson(event);
    ASSERT_TRUE(j.contains("kubernetes"));
    EXPECT_EQ(j["kubernetes"]["host_event"], true);
    EXPECT_FALSE(j["kubernetes"].contains("node_name"));
    EXPECT_FALSE(j["kubernetes"].contains("container_id"));
    EXPECT_EQ(j["kubernetes"].size(), 1u);
}
