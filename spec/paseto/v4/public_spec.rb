# typed: false
# frozen_string_literal: true

require 'shared_examples_for_coders'

RSpec.describe Paseto::V4::Public do
  let(:priv_pem) do
    <<~PRIV
      -----BEGIN PRIVATE KEY-----
      MC4CAQAwBQYDK2VwBCIEIGjBa8BaTU0rxTfIaVzVYtHRQho3qV6z3pvfhGjg2jRI
      -----END PRIVATE KEY-----
    PRIV
  end
  let(:pub_pem) do
    <<~PUB
      -----BEGIN PUBLIC KEY-----
      MCowBQYDK2VwAyEA8NIJGJS8XtHMn6DMuxfOFRLI+qBUtLjxiCdAVius/xM=
      -----END PUBLIC KEY-----
    PUB
  end
  let(:key) { described_class.new(priv_pem) }
  let(:key_pub) { described_class.new(pub_pem) }

  include_examples 'a token coder'

  describe '.generate' do
    it 'returns a new instance' do
      expect(described_class.generate).to be_a(described_class)
    end
  end

  describe '.new' do
    it 'succeds' do
      expect(key).to be_a(described_class)
    end

    it 'errors when provided no keys' do
      expect do
        described_class.new('')
      end.to raise_error(OpenSSL::PKey::PKeyError)
    end

    context 'when provided the wrong key type' do
      let(:pub_pem) do
        <<~P256
          -----BEGIN PUBLIC KEY-----
          MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEslrmxS6agPJYJM+FVAPK5E+di6cSl0ye
          RXHW283RhEyhFXOAkUG4INobjmfiaqpU3L3An3qbWhFOVuYH4cI11jBtfEZb1hKJ
          GQ+NZuU9kXSHVVq/hKFDMBdSFdjGmlMp
          -----END PUBLIC KEY-----
        P256
      end

      it 'raises a CryptoError' do
        expect { key_pub }.to raise_error(Paseto::CryptoError, 'expected Ed25519 key, got id-ecPublicKey')
      end
    end
  end

  describe '#version' do
    it { expect(key.version).to eq('v4') }
  end

  describe '#purpose' do
    it { expect(key.purpose).to eq('public') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v4.public') }
  end

  describe '#public_key' do
    context 'with only a public key' do
      it 'equals to the provided public key' do
        expect(key_pub.key.public_to_pem).to eq pub_pem
      end
    end

    context 'with only a private key' do
      it 'equals the calculated public key for the signing key' do
        expect(key.key.public_to_pem).to eq pub_pem
      end
    end
  end

  describe '#sign' do
    subject(:token) { key.sign(message: 'asdf', footer: '', implicit_assertion: '').to_s }

    it 'returns the expected token' do
      expect(token).to eq('v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4')
    end

    context 'with only a public key' do
      let(:key) { key_pub }

      it 'raises an error' do
        expect { token }.to raise_error(ArgumentError, 'no private key available')
      end

      # rubocop:disable RSpec/NestedGroups

      context 'with openssl/libcrypto 3.0.0 - 3.0.7' do
        it 'raises an error', openssl_3_buggy: true do
          expect { token }.to raise_error(ArgumentError, 'no private key available')
        end
      end

      context 'with openssl/libcrypto 1.1.1' do
        it 'raises an error', openssl_1_1_1: true do
          expect { token }.to raise_error(ArgumentError, 'no private key available')
        end
      end

      context 'with openssl/libcrypto 3.0.8+' do
        it 'raises an error', openssl_3_0_8: true do
          expect { token }.to raise_error(ArgumentError, 'no private key available')
        end
      end

      # rubocop:enable RSpec/NestedGroups
    end
  end

  describe '#verify' do
    subject(:verified) { key_pub.verify(token:) }

    let(:token) do
      Paseto::Token.parse('v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4')
    end

    it 'returns the expected message' do
      expect(verified).to eq('asdf')
    end

    context 'when the message is smaller than the signature size' do
      let(:token) { Paseto::Token.parse('v4.public.YXNkZg') }

      it 'raises an error' do
        expect { verified }.to raise_error(Paseto::ParseError, 'message too short')
      end
    end

    context 'with an invalid signature' do
      let(:token) do
        Paseto::Token.parse('v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm66HVnen0PUYilrNMbXGlsyv7eyaA4')
      end

      it 'raises an error' do
        expect { verified }.to raise_error(Paseto::InvalidSignature)
      end
    end

    context 'when the payload is not UTF-8 encoded' do
      let(:token) do
        Paseto::Token.parse('v4.public.wAmi6msK_S8LX7H8UTl_JmIWyfYkgD9m0g7hlvOn70m2Ho3inqVCGZYdNwYpt84HfMZ0w133Zm0MWGMaA0UWOQw')
      end

      it 'raises an error' do
        expect { verified }.to raise_error(Paseto::ParseError, 'invalid payload encoding')
      end
    end
  end
end
