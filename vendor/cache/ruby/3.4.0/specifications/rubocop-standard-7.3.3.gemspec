# -*- encoding: utf-8 -*-
# stub: rubocop-standard 7.3.3 ruby lib

Gem::Specification.new do |s|
  s.name = "rubocop-standard".freeze
  s.version = "7.3.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "rubygems_mfa_required" => "true" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Garen Torikian".freeze]
  s.date = "2025-03-03"
  s.description = "Enables Shopify\u2019s Ruby Style Guide recommendations (and bundles them with other niceties, like `rubocop-{minitest,performance,rails,rake}`).".freeze
  s.email = ["gjtorikian@gmail.com".freeze]
  s.homepage = "https://github.com/gjtorikian/rubocop-standard".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 2.7".freeze, "< 4.0".freeze])
  s.rubygems_version = "3.5.3".freeze
  s.summary = "Enhanced RuboCop configurations".freeze

  s.installed_by_version = "3.6.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<rubocop>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-minitest>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-performance>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-rails>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-rails-accessibility>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-rake>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-shopify>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rubocop-sorbet>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
end
