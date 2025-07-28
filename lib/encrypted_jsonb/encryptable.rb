# frozen_string_literal: true

require "active_support/concern"
require "encrypted_jsonb/jsonb_encryptor"

module EncryptedJsonb
  module Encryptable
    extend ActiveSupport::Concern

    included do
      class_attribute :encrypted_jsonb_attributes
      self.encrypted_jsonb_attributes = {}
    end

    class_methods do
      def encrypts_jsonb(*attributes)
        attributes.each do |attribute|
          encrypted_jsonb_attributes[attribute] = {
            encryptor: JsonbEncryptor.new(
              primary_key: Rails.application.credentials.active_record_encryption.primary_key,
              deterministic_key: Rails.application.credentials.active_record_encryption.deterministic_key,
            ),
          }

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
