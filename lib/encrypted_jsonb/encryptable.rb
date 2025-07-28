# frozen_string_literal: true

require "active_support/concern"
require "encrypted_jsonb/jsonb_encryptor"

module EncryptedJsonb
  module Encryptable
    extend ActiveSupport::Concern

    # Thread-safe storage for encrypted attributes per class
    ENCRYPTED_ATTRIBUTES = Hash.new { |h, k| h[k] = {}.freeze }.freeze

    included do
      class << self
        def encrypted_jsonb_attributes
          ENCRYPTED_ATTRIBUTES[self]
        end

        def set_encrypted_jsonb_attribute(attribute, config)
          ENCRYPTED_ATTRIBUTES[self] = ENCRYPTED_ATTRIBUTES[self].merge(attribute => config).freeze
        end
      end
    end

    class_methods do
      def encrypts_jsonb(*attributes)
        attributes.each do |attribute|
          config = {
            encryptor: JsonbEncryptor.new(
              primary_key: Rails.application.credentials.active_record_encryption.primary_key,
              deterministic_key: Rails.application.credentials.active_record_encryption.deterministic_key,
            ),
          }

          set_encrypted_jsonb_attribute(attribute, config)

          # Define the attribute accessor
          define_method(attribute) do
            value = super()
            return value if value.nil?

            encryptor = self.class.encrypted_jsonb_attributes[attribute][:encryptor]
            encryptor.decrypt(value)
          end

          # Define the attribute setter
          define_method(:"#{attribute}=") do |value|
            return super(nil) if value.nil?

            encryptor = self.class.encrypted_jsonb_attributes[attribute][:encryptor]
            super(encryptor.encrypt(value))
          end

          # Define query methods
          define_singleton_method(:where_encrypted_json_path_exists) do |path, value|
            encryptor = encrypted_jsonb_attributes[attribute][:encryptor]
            encrypted_value = encryptor.encrypt_for_query(value)
            where("(#{attribute}->>'#{path}')::text = ?", encrypted_value)
          end

          define_singleton_method(:where_encrypted_json_path_contains) do |path, value|
            encryptor = encrypted_jsonb_attributes[attribute][:encryptor]
            encrypted_value = encryptor.encrypt_for_query(value)
            where("(#{attribute}->>'#{path}')::text LIKE ?", "%#{encrypted_value}%")
          end

          define_singleton_method(:where_encrypted_json_path_equals) do |path, value|
            encryptor = encrypted_jsonb_attributes[attribute][:encryptor]
            encrypted_value = encryptor.encrypt_for_query(value)
            where("(#{attribute}->>'#{path}')::text = ?", encrypted_value)
          end
        end
      end
    end
  end
end
