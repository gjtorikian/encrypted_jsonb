# frozen_string_literal: true

require "test_helper"
require "encrypted_jsonb/jsonb_encryptor"
require "benchmark"

module EncryptedJsonb
  class NestingPerformanceTest < ActiveSupport::TestCase
    def setup
      @primary_key = OpenSSL::Random.random_bytes(32)
      @deterministic_key = OpenSSL::Random.random_bytes(32)
      @encryptor = JsonbEncryptor.new(
        primary_key: @primary_key,
        deterministic_key: @deterministic_key,
      )
    end

    # Test various nesting depths
    def test_deep_nesting_limits
      [5, 10, 20, 50, 100].each do |depth|
        nested_data = create_deeply_nested_hash(depth)

        time = Benchmark.realtime do
          encrypted = @encryptor.encrypt(nested_data)
          decrypted = @encryptor.decrypt(encrypted)

          assert_equal(nested_data, decrypted)
        end

        # Assert reasonable performance (under 100ms for typical depths)
        if depth <= 50
          assert_operator(time, :<, 0.1, "Depth #{depth} should encrypt/decrypt in under 100ms, took #{(time * 1000).round(2)}ms")
        end
      end
    end

    # Test various widths (number of keys at each level)
    def test_wide_nesting_performance
      [10, 50, 100, 500, 1000].each do |width|
        wide_data = create_wide_hash(width)

        time = Benchmark.realtime do
          encrypted = @encryptor.encrypt(wide_data)
          decrypted = @encryptor.decrypt(encrypted)

          assert_equal(wide_data, decrypted)
        end

        # Assert reasonable performance scales with width
        expected_max_time = [width * 0.001, 0.1].max # At least 1ms per key or 100ms max

        assert_operator(time, :<, expected_max_time, "Width #{width} should encrypt/decrypt efficiently, took #{(time * 1000).round(2)}ms")
      end
    end

    # Test arrays with various sizes
    def test_array_nesting_performance
      [10, 100, 500, 1000, 5000].each do |size|
        array_data = { "large_array" => create_large_array(size) }

        time = Benchmark.realtime do
          encrypted = @encryptor.encrypt(array_data)
          decrypted = @encryptor.decrypt(encrypted)

          assert_equal(array_data, decrypted)
        end

        # Assert performance scales reasonably with array size
        expected_max_time = [size * 0.001, 0.1].max # At least 1ms per item or 100ms max

        assert_operator(time, :<, expected_max_time, "Array size #{size} should encrypt/decrypt efficiently, took #{(time * 1000).round(2)}ms")
      end
    end

    def test_mixed_complex_structure
      complex_data = {
        "users" => (1..100).map do |i|
          {
            "id" => i,
            "name" => "User #{i}",
            "email" => "user#{i}@example.com",
            "active" => i.even?,
            "profile" => {
              "bio" => "This is user #{i}'s bio",
              "settings" => {
                "theme" => ["dark", "light"],
                "notifications" => {
                  "email" => true,
                  "sms" => false,
                  "push" => i % 3 == 0,
                },
              },
              "tags" => ["tag#{i % 5}", "category#{i % 3}"],
            },
            "posts" => (1..(i % 10 + 1)).map do |j|
              {
                "id" => j,
                "title" => "Post #{j} by User #{i}",
                "content" => "This is the content of post #{j}" * 5,
                "metadata" => {
                  "views" => rand(1000),
                  "likes" => rand(100),
                  "tags" => ["post", "content", "user#{i}"],
                },
              }
            end,
          }
        end,
        "system_config" => {
          "version" => "1.0.0",
          "features" => {
            "encryption" => true,
            "compression" => false,
            "analytics" => {
              "enabled" => true,
              "providers" => ["google", "mixpanel"],
              "settings" => {
                "retention_days" => 30,
                "anonymize" => true,
              },
            },
          },
        },
      }

      key_count = estimate_key_count(complex_data)

      time = Benchmark.realtime do
        encrypted = @encryptor.encrypt(complex_data)
        decrypted = @encryptor.decrypt(encrypted)

        assert_equal(complex_data, decrypted)
      end

      # Assert complex structure handles reasonably (should be under 1 second)
      assert_equal(100, complex_data["users"].length, "Should have 100 users")
      assert_operator(key_count, :>, 5000, "Should have substantial key count for complexity test")
      assert_operator(time, :<, 1.0, "Complex structure should process in under 1 second, took #{(time * 1000).round(2)}ms")
    end

    # Create a reasonably large structure
    def test_memory_usage_with_large_structures
      large_data = {
        "data" => (1..1000).map do |i|
          {
            "id" => i,
            "payload" => {
              "content" => "x" * 100, # 100 chars per item
              "metadata" => {
                "created_at" => "2024-01-01",
                "tags" => (1..5).map { |j| "tag#{j}" },
              },
            },
          }
        end,
      }

      # Measure memory before
      GC.start
      memory_before = determine_memory_usage

      encrypted = @encryptor.encrypt(large_data)
      memory_after_encrypt = determine_memory_usage

      decrypted = @encryptor.decrypt(encrypted)
      determine_memory_usage

      # Verify functionality and reasonable memory usage
      assert_equal(large_data, decrypted)
      assert_equal(1000, large_data["data"].length, "Should have 1000 data items")

      # Memory should increase but not excessively (less than 10x original)
      memory_increase = memory_after_encrypt - memory_before

      assert_operator(memory_increase, :>, 0, "Memory should increase during encryption")
      assert_operator(memory_increase, :<, memory_before * 10, "Memory increase should be reasonable (less than 10x)")
    end

    # Test a structure that approaches practical nesting limits
    # Note: PostgreSQL JSONB has no specific nesting depth limit in recent versions
    # but performance degrades with very deep nesting
    def test_postgresql_jsonb_limits
      # Use a moderate depth that should work reliably
      moderate_depth = 50
      deep_structure = create_deeply_nested_hash(moderate_depth)

      time = Benchmark.realtime do
        encrypted = @encryptor.encrypt(deep_structure)
        decrypted = @encryptor.decrypt(encrypted)

        assert_equal(deep_structure, decrypted)
      end

      # Assert the structure can be handled efficiently
      assert_operator(time, :<, 0.1, "Moderate depth (#{moderate_depth}) should process quickly, took #{(time * 1000).round(2)}ms")

      extreme_structure = create_deeply_nested_hash(200)

      # Test that very deep structures hit Ruby's JSON limit (not PostgreSQL's)
      assert_raises(JSON::NestingError) do
        @encryptor.encrypt(extreme_structure)
      end
    end

    private

    def create_deeply_nested_hash(depth)
      result = { "value" => "leaf_value_#{depth}" }

      (depth - 1).downto(1) do |i|
        result = {
          "level_#{i}" => result,
          "data_#{i}" => "value_at_level_#{i}",
        }
      end

      result
    end

    def create_wide_hash(width)
      result = {}

      width.times do |i|
        result["key_#{i}"] = {
          "id" => i,
          "name" => "Item #{i}",
          "active" => i.even?,
          "data" => "content_#{i}",
        }
      end

      result
    end

    def create_large_array(size)
      Array.new(size) do |i|
        {
          "index" => i,
          "value" => "item_#{i}",
          "metadata" => {
            "created" => "2024-01-01",
            "type" => i % 3 == 0 ? "special" : "normal",
          },
        }
      end
    end

    def estimate_key_count(obj, count = 0)
      case obj
      when Hash
        count += obj.keys.length
        obj.each_value { |v| count = estimate_key_count(v, count) }
      when Array
        obj.each { |v| count = estimate_key_count(v, count) }
      end
      count
    end

    # Simple memory usage approximation
    def determine_memory_usage
      GC.stat[:heap_live_slots] * 40 # rough estimate in bytes
    end

    def format_memory(bytes)
      if bytes > 1_000_000
        "#{(bytes / 1_000_000.0).round(1)}MB"
      elsif bytes > 1_000
        "#{(bytes / 1_000.0).round(1)}KB"
      else
        "#{bytes}B"
      end
    end
  end
end
