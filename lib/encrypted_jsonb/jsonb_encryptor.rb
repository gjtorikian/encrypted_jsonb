# frozen_string_literal: true

require "json"
require "active_support"
require "zlib"
require "active_record/encryption"

module EncryptedJsonb
  class JsonbEncryptor
    class Error < StandardError; end
    class InvalidSignatureError < Error; end

    def initialize(primary_key:, deterministic_key:)
      ActiveRecord::Encryption.configure(
        primary_key: primary_key,
        deterministic_key: deterministic_key,
        key_derivation_salt: SecureRandom.hex(32),
        compressor: Zlib,
      )
      @encryptor = ActiveRecord::Encryption.encryptor
    end

    def encrypt(value)
      return if value.nil?

      encrypted_data = deep_transform(value) do |val|
        next val unless val.is_a?(String) || val.is_a?(Numeric) || val.is_a?(TrueClass) || val.is_a?(FalseClass)

        @encryptor.encrypt(serialize_for_encryption(val), cipher_options: { deterministic: true })
      end

      {
        "message" => encrypted_data,
        "signature" => @encryptor.encrypt(encrypted_data.to_json, cipher_options: { deterministic: true }),
      }
    end

    def decrypt(value)
      return if value.nil?

      data = JSON.parse(value) if value.is_a?(String)
      data ||= value

      verify_signature!(data)
      deep_transform(data["message"]) do |val|
        next val unless val.is_a?(String)

        deserialize_from_encryption(@encryptor.decrypt(val))
      end
    end

    def encrypt_for_query(value)
      return if value.nil?

      @encryptor.encrypt(serialize_for_encryption(value), cipher_options: { deterministic: true })
    end

    private

    def verify_signature!(data)
      expected = @encryptor.decrypt(data["signature"])
      actual = data["message"].to_json
      raise InvalidSignatureError unless expected == actual
    end

    def deep_transform(obj, &block)
      case obj
      when Hash
        obj.transform_values { |v| deep_transform(v, &block) }
      when Array
        obj.map { |v| deep_transform(v, &block) }
      else
        yield(obj)
      end
    end

    def serialize_for_encryption(value)
      case value
      when String
        value
      when Numeric, TrueClass, FalseClass
        "#{value.class}:#{value}"
      else
        value
      end
    end

    def deserialize_from_encryption(value)
      return value unless value.is_a?(String)
      return value unless value.include?(":")

      type, val = value.split(":", 2)
      case type
      when "Integer"
        val.to_i
      when "Float"
        val.to_f
      when "TrueClass"
        true
      when "FalseClass"
        false
      else
        value
      end
    end
  end
end
