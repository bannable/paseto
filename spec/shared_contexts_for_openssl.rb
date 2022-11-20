# typed: false
# frozen_string_literal: true

RSpec.shared_context 'with openssl/libcrypto 3.0.8+' do
  before do
    # If the actual openssl version is not at least 3.0.8, make the gem pretend like it is.
    # This will probably need updating after 3.0.8 is available -- it will probably be
    # raising an ECError or something like that.
    unless Paseto::Util.openssl?(3, 0, 8)
      stub_const('OpenSSL::OPENSSL_VERSION_NUMBER', 0x30000080)
      allow(key).to receive(:sign).and_raise(ArgumentError, 'no private key available')
    end
  end
end

# rubocop:disable RSpec/AnyInstance

RSpec.shared_context 'with openssl/libcrypto 3.0.0 - 3.0.7' do
  before do
    # If the actual openssl version is not 3.0.0-3.0.7, make the gem pretend like it is
    unless Paseto::Util.openssl?(3) && !Paseto::Util.openssl?(3, 0, 8)
      stub_const('OpenSSL::OPENSSL_VERSION_NUMBER', 0x30000020)
      allow_any_instance_of(OpenSSL::PKey::PKey).to receive(:to_text).and_return('ED25519 Public-Key')
    end
  end
end

RSpec.shared_context 'with openssl/libcrypto 1.1.1' do
  before do
    # If the actual openssl version is not 1.1.1, make the gem pretend like it is
    unless (OpenSSL::OPENSSL_VERSION_NUMBER & 0x10101000) == 0x10101000
      stub_const('OpenSSL::OPENSSL_VERSION_NUMBER', 0x10101000)
      allow_any_instance_of(OpenSSL::PKey::PKey).to receive(:to_text).and_return("<INVALID PRIVATE KEY>\n")
    end
  end
end

# rubocop:enable RSpec/AnyInstance

RSpec.configure do |c|
  c.include_context 'with openssl/libcrypto 1.1.1', openssl_1_1_1: true
  c.include_context 'with openssl/libcrypto 3.0.8+', openssl_3_0_8: true
  c.include_context 'with openssl/libcrypto 3.0.0 - 3.0.7', openssl_3_buggy: true
end
