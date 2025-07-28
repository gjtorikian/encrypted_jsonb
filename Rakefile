# frozen_string_literal: true

require "bundler/gem_tasks"
require "rubygems/package_task"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

require "rubocop/rake_task"

RuboCop::RakeTask.new(:rubocop)

task default: [:test, :rubocop]

require "bundler/gem_tasks"
require "rubygems/package_task"
GEMSPEC = Bundler.load_gemspec("encrypted_jsonb.gemspec")
gem_path = Gem::PackageTask.new(GEMSPEC).define
desc "Package the ruby gem"
task "package" => [gem_path]
