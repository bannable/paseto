# frozen_string_literal: true

appraise 'standalone' do
  remove_gem 'parlour'
  remove_gem 'reek'
  remove_gem 'spoom'
end

appraise 'rbnacl' do
  remove_gem 'parlour'
  remove_gem 'reek'
  remove_gem 'spoom'
  gem 'rbnacl', '~> 7.1.1'
end

appraise 'openssl_3.0' do
  remove_gem 'parlour'
  remove_gem 'reek'
  remove_gem 'spoom'
  gem 'openssl', '~> 3.0.0'
end
