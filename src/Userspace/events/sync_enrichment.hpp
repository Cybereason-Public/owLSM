#pragma once

#include "events/event.hpp"
#include "events/kubernetes_event_enrichment.hpp"
#include "rules_managment/rules_metadata_tracker.hpp"
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <memory>

namespace owlsm::events
{

class SyncEventEnrichment
{
public:
    explicit SyncEventEnrichment()
        : m_rules_metadata(owlsm::globals::g_config.rules_config.rules) {}

    void enrich(std::shared_ptr<Event>& event)
    {
        if (event->is_enriched)
        {
            LOG_WARN("Event already enriched. event id: " << event->id);
            return;
        }

        try
        {
            if (event->matched_rule_id > 0)
            {
                event->matched_rule_metadata = m_rules_metadata.get_metadata(event->matched_rule_id);
                LOG_DEBUG("Enriched event with rule metadata: " << event->matched_rule_metadata.description);
            }
            if (owlsm::globals::g_config.kubernetes.enabled)
            {
                m_kubernetes_enrichment.enrich(event->kubernetes, event->process.container_id);
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Failed to enrich event: " << e.what());
            return;
        }

        event->is_enriched = true;
    }

private:
    RulesMetadataTracker m_rules_metadata;
    KubernetesEventEnrichment m_kubernetes_enrichment;
};

class SyncErrorEnrichment
{
public:
    SyncErrorEnrichment() = default;

    void enrich(std::shared_ptr<Error>& error)
    {
        if (error->is_enriched)
        {
            LOG_WARN("Error already enriched");
            return;
        }

        error->is_enriched = true;
    }
};

}

