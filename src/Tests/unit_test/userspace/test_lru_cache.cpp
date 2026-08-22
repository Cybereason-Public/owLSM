#include <gtest/gtest.h>
#include "lru_cache.hpp"

#include <string>

TEST(LruCacheTest, evicts_least_recently_used_when_over_capacity)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);
    cache.put("c", 3);

    EXPECT_EQ(cache.size(), 2u);
    EXPECT_FALSE(cache.get("a").has_value());
    ASSERT_TRUE(cache.get("b").has_value());
    EXPECT_EQ(*cache.get("b"), 2);
    ASSERT_TRUE(cache.get("c").has_value());
    EXPECT_EQ(*cache.get("c"), 3);
}

TEST(LruCacheTest, get_promotes_entry_so_it_is_not_evicted)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);
    ASSERT_TRUE(cache.get("a").has_value());
    cache.put("c", 3);

    EXPECT_TRUE(cache.get("a").has_value());
    EXPECT_FALSE(cache.get("b").has_value());
    EXPECT_TRUE(cache.get("c").has_value());
}

TEST(LruCacheTest, put_updates_existing_without_growing)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("a", 9);
    EXPECT_EQ(cache.size(), 1u);
    ASSERT_TRUE(cache.get("a").has_value());
    EXPECT_EQ(*cache.get("a"), 9);
}

TEST(LruCacheTest, capacity_zero_ignores_puts)
{
    owlsm::LruCache<std::string, int> cache(0);
    cache.put("a", 1);
    EXPECT_EQ(cache.size(), 0u);
    EXPECT_FALSE(cache.get("a").has_value());
}

TEST(LruCacheTest, get_missing_key_returns_empty)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    EXPECT_FALSE(cache.get("missing").has_value());
    EXPECT_EQ(cache.size(), 1u);
}

TEST(LruCacheTest, erase_removes_key_and_is_noop_for_missing)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);
    cache.erase("a");
    cache.erase("missing");
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_FALSE(cache.get("a").has_value());
    ASSERT_TRUE(cache.get("b").has_value());
    EXPECT_EQ(*cache.get("b"), 2);
}

TEST(LruCacheTest, clear_empties_cache)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);
    cache.clear();
    EXPECT_EQ(cache.size(), 0u);
    EXPECT_FALSE(cache.get("a").has_value());
    cache.put("c", 3);
    EXPECT_EQ(cache.size(), 1u);
}

TEST(LruCacheTest, put_existing_promotes_so_other_key_is_evicted)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);
    cache.put("a", 1);
    cache.put("c", 3);

    EXPECT_TRUE(cache.get("a").has_value());
    EXPECT_FALSE(cache.get("b").has_value());
    EXPECT_TRUE(cache.get("c").has_value());
}

TEST(LruCacheTest, capacity_one_keeps_only_latest)
{
    owlsm::LruCache<std::string, int> cache(1);
    cache.put("a", 1);
    cache.put("b", 2);
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_FALSE(cache.get("a").has_value());
    ASSERT_TRUE(cache.get("b").has_value());
    EXPECT_EQ(*cache.get("b"), 2);
}

TEST(LruCacheTest, findIf_returns_match_and_miss)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);

    const auto found = cache.findIf([](const std::string& key, const int)
    {
        return key == "b";
    });
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, 2);

    const auto missing = cache.findIf([](const std::string&, const int)
    {
        return false;
    });
    EXPECT_FALSE(missing.has_value());
}

TEST(LruCacheTest, findIf_promotes_match_so_it_is_not_evicted)
{
    owlsm::LruCache<std::string, int> cache(2);
    cache.put("a", 1);
    cache.put("b", 2);
    ASSERT_TRUE(cache.findIf([](const std::string& key, const int)
    {
        return key == "a";
    }).has_value());
    cache.put("c", 3);

    EXPECT_TRUE(cache.get("a").has_value());
    EXPECT_FALSE(cache.get("b").has_value());
    EXPECT_TRUE(cache.get("c").has_value());
}
