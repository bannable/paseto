# frozen_string_literal: true

appraise 'standalone' do
  group :development do
    remove_gem 'appraisal'
    remove_gem 'debug'
    remove_gem 'parlour'
    remove_gem 'reek'
    remove_gem 'spoom'
    remove_gem 'tapioca'
  end
end

appraise 'rbnacl' do
  group :development do
    remove_gem 'appraisal'
    remove_gem 'debug'
    remove_gem 'parlour'
    remove_gem 'reek'
    remove_gem 'spoom'
    remove_gem 'tapioca'
  end
  gem 'rbnacl', '~> 7.1.1'
end

appraise 'openssl_3.0' do
  group :development do
    remove_gem 'appraisal'
    remove_gem 'debug'
    remove_gem 'parlour'
    remove_gem 'reek'
    remove_gem 'spoom'
    remove_gem 'tapioca'
  end
  gem 'openssl', '~> 3.0.0', '>= 3.0.2'
end
