require 'rubygems'
require 'bundler/setup'
require 'casclient'
require 'riot'
require 'riot/rr'
require 'riot-rack'
require 'action_pack'
require 'ruby-debug'
Debugger.start

RAILS_ROOT = "#{File.dirname(__FILE__)}/.." unless defined?(RAILS_ROOT)

Riot.reporter = Riot::VerboseStoryReporter
