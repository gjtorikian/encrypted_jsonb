# frozen_string_literal: true

require "test_helper"
require "encrypted_jsonb/jsonb_encryptor"

module EncryptedJsonb
  class EncodingEdgeCasesTest < ActiveSupport::TestCase
    def setup
      @primary_key = OpenSSL::Random.random_bytes(32)
      @deterministic_key = OpenSSL::Random.random_bytes(32)
      @encryptor = JsonbEncryptor.new(
        primary_key: @primary_key,
        deterministic_key: @deterministic_key,
      )
    end

    def test_handles_arrays_without_encoding_method
      original = {
        "tags" => ["ruby", "rails", "encryption"],
        "numbers" => [1, 2, 3, 4, 5],
        "mixed" => [1, "string", true, nil],
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_equal(["ruby", "rails", "encryption"], decrypted["tags"])
      assert_equal([1, 2, 3, 4, 5], decrypted["numbers"])
      assert_equal([1, "string", true, nil], decrypted["mixed"])
    end

    def test_handles_hashes_without_encoding_method
      original = {
        "config" => {
          "timeout" => 30,
          "retries" => 3,
          "enabled" => true,
        },
        "metadata" => {
          "created_at" => "2024-01-01",
          "version" => "1.0.0",
        },
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_equal(30, decrypted["config"]["timeout"])
      assert_equal("1.0.0", decrypted["metadata"]["version"])
    end

    def test_handles_deeply_nested_arrays_and_hashes
      original = {
        "data" => {
          "users" => [
            {
              "name" => "Alice",
              "roles" => ["admin", "user"],
              "permissions" => {
                "read" => true,
                "write" => false,
                "delete" => false,
              },
            },
            {
              "name" => "Bob",
              "roles" => ["user"],
              "permissions" => {
                "read" => true,
                "write" => true,
                "delete" => false,
              },
            },
          ],
          "settings" => {
            "notifications" => {
              "email" => true,
              "sms" => false,
              "types" => ["alert", "warning", "info"],
            },
          },
        },
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_equal("Alice", decrypted["data"]["users"][0]["name"])
      assert_equal(["admin", "user"], decrypted["data"]["users"][0]["roles"])
      assert_equal(["alert", "warning", "info"], decrypted["data"]["settings"]["notifications"]["types"])
    end

    def test_handles_empty_arrays_and_hashes
      original = {
        "empty_array" => [],
        "empty_hash" => {},
        "nested" => {
          "empty_array" => [],
          "empty_hash" => {},
        },
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_empty(decrypted["empty_array"])
      assert_empty(decrypted["empty_hash"])
    end

    def test_handles_numeric_types_in_arrays
      original = {
        "integers" => [1, 42, -100, 0],
        "floats" => [1.5, -3.14, 0.0],
        "mixed_numbers" => [1, 2.5, -10, 0.0],
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_equal([1, 42, -100, 0], decrypted["integers"])
      assert_equal([1.5, -3.14, 0.0], decrypted["floats"])
      assert_equal([1, 2.5, -10, 0.0], decrypted["mixed_numbers"])
    end

    def test_handles_boolean_values_in_arrays
      original = {
        "flags" => [true, false, true],
        "mixed_with_booleans" => [1, true, "string", false, nil],
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_equal([true, false, true], decrypted["flags"])
      assert_equal([1, true, "string", false, nil], decrypted["mixed_with_booleans"])
    end

    def test_handles_nil_values_in_arrays
      original = {
        "sparse_array" => [1, nil, "hello", nil, true],
        "all_nils" => [nil, nil, nil],
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_equal([1, nil, "hello", nil, true], decrypted["sparse_array"])
      assert_equal([nil, nil, nil], decrypted["all_nils"])
    end

    def test_arrays_and_hashes_dont_respond_to_encoding
      test_array = [1, 2, 3]
      test_hash = { "key" => "value" }

      refute_respond_to(test_array, :encoding, "Arrays should not respond to :encoding")
      refute_respond_to(test_hash, :encoding, "Hashes should not respond to :encoding")
    end

    def test_string_values_do_respond_to_encoding
      test_string = "hello world"

      assert_respond_to(test_string, :encoding, "Strings should respond to :encoding")
      assert_equal(Encoding::UTF_8, test_string.encoding)
    end

    def test_numeric_and_boolean_values_dont_respond_to_encoding
      refute_respond_to(42, :encoding, "Integers should not respond to :encoding")
      refute_respond_to(3.14, :encoding, "Floats should not respond to :encoding")
      refute_respond_to(true, :encoding, "Booleans should not respond to :encoding")
      refute_respond_to(false, :encoding, "Booleans should not respond to :encoding")
    end

    def test_encryption_preserves_data_types_in_complex_structures
      original = {
        "user_data" => {
          "id" => 123,
          "name" => "John Doe",
          "email" => "john@example.com",
          "active" => true,
          "last_login" => nil,
          "roles" => ["admin", "user"],
          "preferences" => {
            "theme" => "dark",
            "notifications" => true,
            "limits" => {
              "daily" => 100,
              "monthly" => 3000,
            },
          },
          "recent_actions" => [
            { "action" => "login", "timestamp" => "2024-01-01T10:00:00Z" },
            { "action" => "update_profile", "timestamp" => "2024-01-01T10:30:00Z" },
          ],
        },
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)

      # Verify specific type preservation
      assert_equal(123, decrypted["user_data"]["id"])
      assert_kind_of(Integer, decrypted["user_data"]["id"])

      assert_equal("John Doe", decrypted["user_data"]["name"])
      assert_kind_of(String, decrypted["user_data"]["name"])

      assert(decrypted["user_data"]["active"])
      assert_kind_of(TrueClass, decrypted["user_data"]["active"])

      assert_nil(decrypted["user_data"]["last_login"])

      assert_equal(["admin", "user"], decrypted["user_data"]["roles"])
      assert_kind_of(Array, decrypted["user_data"]["roles"])

      assert_equal({ "theme" => "dark", "notifications" => true, "limits" => { "daily" => 100, "monthly" => 3000 } }, decrypted["user_data"]["preferences"])
      assert_kind_of(Hash, decrypted["user_data"]["preferences"])

      assert_equal(100, decrypted["user_data"]["preferences"]["limits"]["daily"])
      assert_kind_of(Integer, decrypted["user_data"]["preferences"]["limits"]["daily"])
    end

    def test_deterministic_encryption_works_with_arrays_and_hashes
      original1 = { "tags" => ["ruby", "rails"], "config" => { "timeout" => 30 } }
      original2 = { "tags" => ["ruby", "rails"], "config" => { "timeout" => 30 } }

      encrypted1 = @encryptor.encrypt(original1)
      encrypted2 = @encryptor.encrypt(original2)

      # The overall structure should be the same due to deterministic encryption
      assert_equal(encrypted1["message"]["tags"], encrypted2["message"]["tags"])
      assert_equal(encrypted1["message"]["config"], encrypted2["message"]["config"])

      # But signatures will be different due to the overall message structure
      assert_equal(encrypted1["signature"], encrypted2["signature"])
    end
  end
end
