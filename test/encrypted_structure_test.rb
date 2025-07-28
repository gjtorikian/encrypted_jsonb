# frozen_string_literal: true

require "test_helper"
require "encrypted_jsonb/jsonb_encryptor"
require "json"

module EncryptedJsonb
  class EncryptedStructureTest < ActiveSupport::TestCase
    def setup
      @primary_key = OpenSSL::Random.random_bytes(32)
      @deterministic_key = OpenSSL::Random.random_bytes(32)
      @encryptor = JsonbEncryptor.new(
        primary_key: @primary_key,
        deterministic_key: @deterministic_key,
      )
    end

    def test_simple_hash_encrypted_structure
      original = {
        "name" => "John Doe",
        "age" => 30,
        "active" => true,
      }

      encrypted = @encryptor.encrypt(original)

      # Verify the structure
      assert_kind_of(Hash, encrypted)
      assert(encrypted.key?("message"), "Should have 'message' key")
      assert(encrypted.key?("signature"), "Should have 'signature' key")

      # Check that message preserves original structure but encrypts values
      message = encrypted["message"]

      assert_kind_of(Hash, message)
      assert(message.key?("name"))
      assert(message.key?("age"))
      assert(message.key?("active"))

      # All values should be encrypted strings
      assert_kind_of(String, message["name"])
      assert_kind_of(String, message["age"])
      assert_kind_of(String, message["active"])

      # Signature should be encrypted
      assert_kind_of(String, encrypted["signature"])
    end

    def test_nested_structure_with_arrays
      original = {
        "user" => {
          "profile" => {
            "name" => "Jane Doe",
            "age" => 25,
          },
          "roles" => ["admin", "user"],
          "permissions" => {
            "read" => true,
            "write" => false,
          },
        },
        "metadata" => {
          "created_at" => "2024-01-01",
          "tags" => ["important", "verified"],
        },
      }

      encrypted = @encryptor.encrypt(original)

      # Verify nested structure preservation
      message = encrypted["message"]

      # Check that Hash structures are preserved
      assert_kind_of(Hash, message["user"])
      assert_kind_of(Hash, message["user"]["profile"])
      assert_kind_of(Hash, message["user"]["permissions"])
      assert_kind_of(Hash, message["metadata"])

      # Check that Array structures are preserved
      assert_kind_of(Array, message["user"]["roles"])
      assert_kind_of(Array, message["metadata"]["tags"])

      # Check that primitive values are encrypted
      assert_kind_of(String, message["user"]["profile"]["name"])
      assert_kind_of(String, message["user"]["profile"]["age"])
      assert_kind_of(String, message["user"]["permissions"]["read"])
      assert_kind_of(String, message["user"]["permissions"]["write"])
      assert_kind_of(String, message["metadata"]["created_at"])

      # Check that array elements are encrypted
      assert_kind_of(String, message["user"]["roles"][0])
      assert_kind_of(String, message["user"]["roles"][1])
      assert_kind_of(String, message["metadata"]["tags"][0])
      assert_kind_of(String, message["metadata"]["tags"][1])
    end

    def test_encrypted_value_format
      original = { "test" => "hello world" }
      encrypted = @encryptor.encrypt(original)

      # Verify encrypted value format
      encrypted_value = encrypted["message"]["test"]

      assert_kind_of(String, encrypted_value, "Encrypted value should be a string")
      refute_empty(encrypted_value, "Encrypted value should not be empty")
      assert_includes(encrypted_value, '"p":', "Should contain payload marker")
      assert_includes(encrypted_value, '"h":', "Should contain header marker")
      assert_includes(encrypted_value, '"iv":', "Should contain IV marker")
      assert_includes(encrypted_value, '"at":', "Should contain auth tag marker")

      # Test that decryption works
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
    end

    def test_signature_format
      original = { "test" => "value" }
      encrypted = @encryptor.encrypt(original)

      signature = encrypted["signature"]

      # Verify signature is present and is a string
      assert_kind_of(String, signature, "Signature should be a string")
      refute_empty(signature, "Signature should not be empty")

      # Verify signature contains encrypted data structure
      assert_includes(signature, '"p":', "Signature should contain encrypted payload marker")
      assert_includes(signature, '"h":', "Signature should contain encrypted header marker")

      # The signature should be an encrypted version of the message JSON
      message_json = encrypted["message"].to_json

      assert_kind_of(String, message_json, "Message JSON should be a string")
      refute_empty(message_json, "Message JSON should not be empty")
    end

    def test_deterministic_encryption_same_structure
      value1 = { "secret" => "same value" }
      value2 = { "secret" => "same value" }

      encrypted1 = @encryptor.encrypt(value1)
      encrypted2 = @encryptor.encrypt(value2)

      # Due to deterministic encryption, the encrypted values should be identical
      assert_equal(encrypted1["message"]["secret"], encrypted2["message"]["secret"])
      assert_equal(encrypted1["signature"], encrypted2["signature"])
    end

    def test_different_values_different_encryption
      value1 = { "secret" => "value one" }
      value2 = { "secret" => "value two" }

      encrypted1 = @encryptor.encrypt(value1)
      encrypted2 = @encryptor.encrypt(value2)

      # Different values should produce different encrypted results
      refute_equal(encrypted1["message"]["secret"], encrypted2["message"]["secret"])
      refute_equal(encrypted1["signature"], encrypted2["signature"])
    end

    def test_nil_and_empty_values_structure
      original = {
        "nil_value" => nil,
        "empty_string" => "",
        "empty_array" => [],
        "empty_hash" => {},
        "zero" => 0,
        "false_value" => false,
      }

      encrypted = @encryptor.encrypt(original)

      message = encrypted["message"]

      # Check how different "empty" values are handled
      assert_nil(message["nil_value"], "nil should remain nil")
      assert_kind_of(String, message["empty_string"], "empty string should be encrypted")
      assert_kind_of(Array, message["empty_array"], "empty array should remain array")
      assert_empty(message["empty_array"], "empty array should be empty")
      assert_kind_of(Hash, message["empty_hash"], "empty hash should remain hash")
      assert_empty(message["empty_hash"], "empty hash should be empty")
      assert_kind_of(String, message["zero"], "zero should be encrypted")
      assert_kind_of(String, message["false_value"], "false should be encrypted")
    end

    def test_query_encryption_format
      value = "searchable value"
      query_encrypted = @encryptor.encrypt_for_query(value)

      # Verify query encrypted format
      assert_kind_of(String, query_encrypted, "Query encrypted value should be a string")
      refute_empty(query_encrypted, "Query encrypted value should not be empty")
      assert_includes(query_encrypted, '"p":', "Should contain payload marker")
      assert_includes(query_encrypted, '"h":', "Should contain header marker")

      # Query encryption should be deterministic
      query_encrypted2 = @encryptor.encrypt_for_query(value)

      assert_equal(query_encrypted, query_encrypted2, "Query encryption should be deterministic")

      # Different values should produce different encrypted results
      different_encrypted = @encryptor.encrypt_for_query("different value")

      refute_equal(query_encrypted, different_encrypted, "Different values should encrypt differently")
    end
  end
end
