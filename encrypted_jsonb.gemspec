# frozen_string_literal: true

require_relative "lib/encrypted_jsonb/version"

Gem::Specification.new do |spec|
  spec.name = "encrypted_jsonb"
  spec.version = EncryptedJsonb::VERSION
  spec.authors = ["Garen J. Torikian"]
  spec.email = ["gjtorikian@gmail.com"]

  spec.summary = "Deterministic encryption and querability for JSONB fields in Rails"
  spec.description = "A gem that provides deterministic encryption for JSONB fields while maintaining queryability. It encrypts values within JSON structures while preserving the structure itself, allowing for efficient querying of encrypted data."
  spec.homepage = "https://github.com/gjtorikian/encrypted_jsonb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.metadata["funding_uri"] = "https://github.com/sponsors/gjtorikian/"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(["git", "ls-files", "-z"], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?("bin/", "test/", "spec/", "features/", ".git", ".github", "appveyor", "Gemfile")
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency("pg", "~> 1.5")
  spec.add_dependency("rails", ">= 8.0.0")

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
