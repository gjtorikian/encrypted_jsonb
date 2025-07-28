# frozen_string_literal: true

require "test_helper"
require "openssl"
require "encrypted_jsonb/jsonb_encryptor"

module EncryptedJsonb
  class JsonbEncryptorTest < ActiveSupport::TestCase
    def setup
      @primary_key = OpenSSL::Random.random_bytes(32)
      @deterministic_key = OpenSSL::Random.random_bytes(32)
      @encryptor = JsonbEncryptor.new(
        primary_key: @primary_key,
        deterministic_key: @deterministic_key,
      )
    end

    def test_encrypts_and_decrypts_simple_hash
      original = {
        "name" => "John Doe",
        "age" => 30,
        "active" => true,
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_kind_of(String, encrypted["message"]["name"])
      assert_kind_of(String, encrypted["message"]["age"])
      assert_kind_of(String, encrypted["message"]["active"])
      assert(encrypted["signature"])
    end

    def test_encrypts_and_decrypts_nested_structure
      original = {
        "user" => {
          "profile" => {
            "name" => "Jane Doe",
            "preferences" => {
              "theme" => "dark",
              "notifications" => true,
            },
          },
          "posts" => [
            { "title" => "First Post", "content" => "Hello World" },
            { "title" => "Second Post", "content" => "Goodbye World" },
          ],
        },
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
      assert_kind_of(String, encrypted["message"]["user"]["profile"]["name"])
      assert_kind_of(String, encrypted["message"]["user"]["posts"][0]["title"])
    end

    def test_deterministic_encryption
      original = { "secret" => "value" }

      encrypted1 = @encryptor.encrypt(original)
      encrypted2 = @encryptor.encrypt(original)

      assert_equal(encrypted1["message"]["secret"], encrypted2["message"]["secret"])
    end

    def test_handles_nil_values
      original = {
        "name" => nil,
        "data" => { "value" => nil },
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
    end

    def test_raises_error_on_tampered_data
      original = { "secret" => "value" }
      encrypted = @encryptor.encrypt(original)

      # Tamper with the data
      encrypted["message"]["secret"] = "tampered"

      assert_raises(JsonbEncryptor::InvalidSignatureError) do
        @encryptor.decrypt(encrypted)
      end
    end

    def test_preserves_non_encryptable_values
      original = {
        "array" => [1, 2, 3],
        "hash" => { "key" => "value" },
        "nil" => nil,
      }

      encrypted = @encryptor.encrypt(original)
      decrypted = @encryptor.decrypt(encrypted)

      assert_equal(original, decrypted)
    end

    def test_deterministic_encryption_for_querying
      value1 = "test value"
      value2 = "test value"

      encrypted1 = @encryptor.encrypt_for_query(value1)
      encrypted2 = @encryptor.encrypt_for_query(value2)

      assert_equal(encrypted1, encrypted2, "Same input should produce same encrypted output for querying")
    end

    def test_different_values_produce_different_encrypted_output
      value1 = "test value 1"
      value2 = "test value 2"

      encrypted1 = @encryptor.encrypt_for_query(value1)
      encrypted2 = @encryptor.encrypt_for_query(value2)

      refute_equal(encrypted1, encrypted2, "Different inputs should produce different encrypted outputs")
    end
  end
end
