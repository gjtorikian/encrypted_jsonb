# frozen_string_literal: true

require "test_helper"
require "encrypted_jsonb/query_helpers"
require "encrypted_jsonb/jsonb_encryptor"

module EncryptedJsonb
  class QueryHelpersTest < ActiveSupport::TestCase
    # Mock AR::Base functionality we need
    class MockModel
      include QueryHelpers

      attr_reader :encryptor

      def initialize
        @encryptor = JsonbEncryptor.new(
          primary_key: OpenSSL::Random.random_bytes(32),
          deterministic_key: OpenSSL::Random.random_bytes(32),
        )
        @where_clauses = []
      end

      def where(*args)
        @where_clauses << args
        self
      end

      def to_sql
        case @where_clauses.last
        when Array
          sql = @where_clauses.last[0]
          binds = @where_clauses.last[1..-1]

          # Simple bind param replacement for testing
          binds.each do |bind|
            sql = sql.sub("?", bind.is_a?(Array) ? bind.join(",") : bind.inspect)
          end

          "SELECT * FROM mock_models WHERE #{sql}"
        when String
          "SELECT * FROM mock_models WHERE #{@where_clauses.last}"
        when Hash
          "SELECT * FROM mock_models WHERE #{@where_clauses.last.map { |k, v| "#{k} = #{v.inspect}" }.join(" AND ")}"
        end
      end
    end

    def setup
      @model = MockModel.new
    end

    def test_where_encrypted_jsonb_equals_generates_correct_sql
      relation = @model.where_encrypted_jsonb_equals(:data, ["user", "name"], "John")
      sql = relation.to_sql

      assert_includes(sql, '"data" #>>')
      assert_includes(sql, "{user,name}")
      assert_includes(sql, "=")
      assert(encrypted_value?(sql), "SQL should contain encrypted value pattern: #{sql}")
    end

    def test_where_encrypted_jsonb_contains_generates_correct_sql
      query = { "user" => { "name" => "John" } }
      relation = @model.where_encrypted_jsonb_contains(:data, query)
      sql = relation.to_sql

      assert_includes(sql, '"data" @>')
      assert_includes(sql, "message")
      assert_includes(sql, "user")
      assert_includes(sql, "name")
      assert(encrypted_value?(sql), "SQL should contain encrypted value pattern: #{sql}")
    end

    def test_where_encrypted_jsonb_exists_generates_correct_sql
      relation = @model.where_encrypted_jsonb_exists(:data, ["user", "name"])
      sql = relation.to_sql

      assert_includes(sql, '"data" #>')
      assert_includes(sql, "{user,name}")
      assert_includes(sql, "IS NOT NULL")
    end

    def test_where_encrypted_jsonb_in_generates_correct_sql
      values = ["John", "Jane"]
      relation = @model.where_encrypted_jsonb_in(:data, ["user", "name"], values)
      sql = relation.to_sql

      assert_includes(sql, '"data" #>>')
      assert_includes(sql, "{user,name}")
      assert_includes(sql, "IN")
      assert(encrypted_values?(sql, 2), "SQL should contain 2 encrypted values: #{sql}")
    end

    def test_where_encrypted_jsonb_array_contains_generates_correct_sql
      relation = @model.where_encrypted_jsonb_array_contains(:data, ["user", "roles"], "admin")
      sql = relation.to_sql

      assert_includes(sql, "ANY")
      assert_includes(sql, '"data" #>>')
      assert_includes(sql, "{user,roles}")
      assert(encrypted_value?(sql), "SQL should contain encrypted value pattern: #{sql}")
    end

    # Security Tests

    def test_sql_injection_in_column_name
      malicious_column = "data; DROP TABLE users--"
      relation = @model.where_encrypted_jsonb_equals(malicious_column, ["path"], "value")
      sql = relation.to_sql

      assert_includes(sql, '"data; DROP TABLE users--"')
      assert_not_includes(sql.gsub('"data; DROP TABLE users--"', ""), "DROP TABLE")
    end

    def test_sql_injection_in_path
      malicious_path = "user'; DROP TABLE users--"
      relation = @model.where_encrypted_jsonb_equals(:data, [malicious_path], "value")
      sql = relation.to_sql

      assert_includes(sql, malicious_path)
      assert_not_includes(sql.gsub(malicious_path, ""), "DROP TABLE")
    end

    def test_sql_injection_in_value
      malicious_value = "value'; DROP TABLE users--"
      relation = @model.where_encrypted_jsonb_equals(:data, ["path"], malicious_value)
      sql = relation.to_sql

      assert(encrypted_value?(sql), "SQL should contain encrypted value pattern: #{sql}")
      assert_not_includes(sql, "DROP TABLE")
    end

    def test_sql_injection_in_array_values
      malicious_values = ["normal", "value'; DROP TABLE users--"]
      relation = @model.where_encrypted_jsonb_in(:data, ["path"], malicious_values)
      sql = relation.to_sql

      assert(encrypted_values?(sql, 2), "SQL should contain 2 encrypted values: #{sql}")
      assert_not_includes(sql, "DROP TABLE")
    end

    def test_deep_transform_values_for_query_security
      malicious_hash = {
        "user" => {
          "name" => "value'; DROP TABLE users--",
          "role" => "admin'; DELETE FROM users--",
        },
      }

      relation = @model.where_encrypted_jsonb_contains(:data, malicious_hash)
      sql = relation.to_sql

      assert_not_includes(sql, "DROP TABLE")
      assert_not_includes(sql, "DELETE FROM")
      assert(encrypted_values?(sql, 2), "SQL should contain 2 encrypted values: #{sql}")
    end

    private

    def encrypted_value?(sql)
      # Look for the structure of an encrypted value, handling JSON escaping
      sql.match?(/p[":\\]+"/) &&
        sql.match?(/h[":\\]+"/) &&
        sql.match?(/iv[":\\]+"/) &&
        sql.match?(/at[":\\]+"/)
    end

    def encrypted_values?(sql, count)
      # Count occurrences of the 'p' field in encrypted values, handling JSON escaping
      sql.scan(/p[":\\]+"/).length == count
    end
  end
end
