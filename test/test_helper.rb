# frozen_string_literal: true

require "minitest/autorun"
require "minitest/pride"

require "active_support"
require "active_support/test_case"
require "encrypted_jsonb"
require "active_record"

if ENV.fetch("DEBUG", false)
  require "amazing_print"
  require "debug"
end

# Configure ActiveSupport::TestCase as the base class for all tests
module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)
  end
end
