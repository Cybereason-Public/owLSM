#pragma once

#include <cstddef>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

namespace owlsm
{

template<typename TKey, typename TValue>
class LruCache
{
public:
    explicit LruCache(const std::size_t capacity) : m_capacity(capacity)
    {
    }

    void put(const TKey& key, TValue value)
    {
        if (m_capacity == 0)
        {
            return;
        }

        const auto existing = m_index.find(key);
        if (existing != m_index.end())
        {
            existing->second->second = std::move(value);
            m_items.splice(m_items.begin(), m_items, existing->second);
            return;
        }

        m_items.emplace_front(key, std::move(value));
        m_index.emplace(m_items.front().first, m_items.begin());
        if (m_items.size() > m_capacity)
        {
            m_index.erase(m_items.back().first);
            m_items.pop_back();
        }
    }

    std::optional<TValue> get(const TKey& key)
    {
        const auto existing = m_index.find(key);
        if (existing == m_index.end())
        {
            return std::nullopt;
        }
        m_items.splice(m_items.begin(), m_items, existing->second);
        return existing->second->second;
    }

    template<typename TPred>
    std::optional<TValue> findIf(TPred pred)
    {
        for (auto it = m_items.begin(); it != m_items.end(); ++it)
        {
            if (pred(it->first, it->second))
            {
                m_items.splice(m_items.begin(), m_items, it);
                return it->second;
            }
        }
        return std::nullopt;
    }

    void erase(const TKey& key)
    {
        const auto existing = m_index.find(key);
        if (existing == m_index.end())
        {
            return;
        }
        m_items.erase(existing->second);
        m_index.erase(existing);
    }

    void clear()
    {
        m_items.clear();
        m_index.clear();
    }

    std::size_t size() const
    {
        return m_items.size();
    }

private:
    using Item = std::pair<TKey, TValue>;
    using ItemList = std::list<Item>;

    std::size_t m_capacity = 0;
    ItemList m_items;
    std::unordered_map<TKey, typename ItemList::iterator> m_index;
};

}
