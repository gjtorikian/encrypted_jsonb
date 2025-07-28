# frozen_string_literal: true

require "active_support/concern"

module EncryptedJsonb
  module QueryHelpers
    extend ActiveSupport::Concern

    # @param column [String, Symbol] The JSONB column name
    # @param path [String, Array<String>] The JSON path to search in (e.g., '{user,profile,name}' or ['user', 'profile', 'name'])
    # @param value [String, Numeric, Boolean] The value to search for
    # @return [ActiveRecord::Relation]
    def where_encrypted_jsonb_equals(column, path, value)
      path = Array(path).join(",")
      path_array = "{#{path}}"
      encrypted_value = @encryptor.encrypt_for_query(value)

      where("#{quote_column(column)} #>> ? = ?", path_array, encrypted_value)
    end

    # @param column [String, Symbol] The JSONB column name
    # @param query_hash [Hash] A hash of path => value pairs to search for
    # @return [ActiveRecord::Relation]
    def where_encrypted_jsonb_contains(column, query_hash)
      encrypted_hash = deep_transform_values_for_query(query_hash)
      encrypted_json = { "message" => encrypted_hash }.to_json

      where("#{quote_column(column)} @> ?", encrypted_json)
    end

    # @param column [String, Symbol] The JSONB column name
    # @param path [String, Array<String>] The JSON path to check existence of
    # @return [ActiveRecord::Relation]
    def where_encrypted_jsonb_exists(column, path)
      path = Array(path).join(",")
      path_array = "{#{path}}"

      where("#{quote_column(column)} #> ? IS NOT NULL", path_array)
    end

    # @param column [String, Symbol] The JSONB column name
    # @param path [String, Array<String>] The JSON path to search in
    # @param values [Array] Array of values to search for
    # @return [ActiveRecord::Relation]
    def where_encrypted_jsonb_in(column, path, values)
      path = Array(path).join(",")
      path_array = "{#{path}}"
      encrypted_values = values.map { |value| @encryptor.encrypt_for_query(value) }

      where("#{quote_column(column)} #>> ? IN (?)", path_array, encrypted_values)
    end

    # @param column [String, Symbol] The JSONB column name
    # @param path [String, Array<String>] The JSON path to the array
    # @param value Any value that should be in the array
    # @return [ActiveRecord::Relation]
    def where_encrypted_jsonb_array_contains(column, path, value)
      path = Array(path).join(",")
      path_array = "{#{path}}"
      encrypted_value = @encryptor.encrypt_for_query(value)

      where("? = ANY (#{quote_column(column)} #>> ? ::text[])", encrypted_value, path_array)
    end

    private

    def deep_transform_values_for_query(hash)
      hash.transform_values do |value|
        if value.is_a?(Hash)
          deep_transform_values_for_query(value)
        else
          @encryptor.encrypt_for_query(value)
        end
      end
    end

    def quote_column(column)
      column.to_s.include?(".") ? column.to_s : "\"#{column}\""
    end
  end
end
