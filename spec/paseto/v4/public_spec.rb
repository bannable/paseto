# typed: false
# frozen_string_literal: true

require 'shared_examples_for_keys'

RSpec.describe 'Paseto::V4::Public', :sodium do
  let(:described_class) { Paseto::V4::Public }

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

  include_examples 'AsymmetricKey'

  describe '.new' do
    it 'succeds' do
      expect(key).to be_a(described_class)
    end

    it 'errors when provided no keys' do
      expect { described_class.new('') }.to raise_error(Paseto::ParseError)
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
      let(:key) { described_class.new(pub_pem) }

      it 'raises a LucidityError' do
        expect { key }.to raise_error(Paseto::LucidityError, 'expected Ed25519 key, got id-ecPublicKey')
      end
    end
  end

  describe '.from_keypair' do
    let(:keypair) do
      '5f445f215af4331f567339bc83308b16694f6b8e70e1d0e24ce192e91e02831' \
        '0bd3c6270088ea35eafdd38edfb7bfd107107df533b82903b39576ccb6c8c48e0'
    end
    let(:key) { described_class.from_keypair(Paseto::Util.decode_hex(keypair)) }

    it 'succeeds' do
      expect(key).to be_a described_class
    end

    context 'with an invalid keypair' do
      let(:keypair) do
        '5f445f215af4331f567339bc83308b16694f6b8e70e1d0e24ce192e91e02831' \
          '00000000000000000000000000000000000000000000000000000000000000000'
      end

      it 'raises InvalidKeyPair' do
        expect { key }.to raise_error(Paseto::InvalidKeyPair, 'public key does not match private')
      end
    end
  end

  describe '#version' do
    it { expect(key.version).to eq('v4') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v4.public') }
  end

  describe '#public_to_pem' do
    context 'with a public key' do
      let(:key) { described_class.new(pub_pem) }

      it 'matches the public PEM' do
        expect(key.public_to_pem).to eq pub_pem
      end
    end

    context 'with a private key' do
      it 'matches the public PEM' do
        expect(key.public_to_pem).to eq pub_pem
      end
    end
  end

  describe '#private_to_pem' do
    context 'with a public key' do
      let(:key) { described_class.new(pub_pem) }

      it 'raises an ArgumentError' do
        expect { key.private_to_pem }.to raise_error(ArgumentError, 'no private key available')
      end
    end

    context 'with a private key' do
      it 'matches the private PEM' do
        expect(key.private_to_pem).to eq priv_pem
      end
    end
  end

  describe '#to_bytes' do
    context 'with only a public key' do
      subject(:bytes) { described_class.new(pub_pem).to_bytes }

      it 'raises an error' do
        expect { bytes }.to raise_error(ArgumentError, 'no private key available')
      end
    end
  end

  describe '#sign' do
    subject(:token) { key.sign(message: 'asdf', footer: '', implicit_assertion: '').to_s }

    it 'returns the expected token' do
      expect(token).to eq('v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4')
    end

    context 'with only a public key' do
      let(:key) { described_class.new(pub_pem) }

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
    subject(:verified) { key.verify(token: token) }

    let(:key) { described_class.new(pub_pem) }
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

  describe '#to_paserk' do
    let(:key_bytes) { Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f') }

    context 'with a secret key' do
      let(:key) { described_class.new(RbNaCl::SigningKey.new(key_bytes)) }

      it 'encodes to the expected k4.secret' do
        expect(key.paserk).to eq('k4.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ')
      end
    end

    context 'with a secret key and requesting a public paserk' do
      let(:key) { described_class.new(RbNaCl::SigningKey.new(key_bytes)) }

      it 'encodes to the expected k4.public' do
        expect(key.public_paserk).to eq('k4.public.HOVqSMgv-ZFioUvFRGEmdOXWH7kxfmXUBVeA_by03DU')
      end
    end

    context 'with a public key' do
      let(:key) { described_class.new(RbNaCl::VerifyKey.new(key_bytes)) }

      it 'encodes to the expected k4.public' do
        expect(key.paserk).to eq('k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8')
      end
    end
  end

  describe '#id' do
    let(:key_bytes) { '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' }

    context 'with a public key' do
      let(:key) { described_class.from_public_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k4.pid' do
        expect(key.id).to eq('k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs')
      end
    end

    context 'with a secret key' do
      let(:key_bytes) do
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' \
          '1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
      end
      let(:key) { described_class.from_keypair(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k4.sid' do
        expect(key.id).to eq('k4.sid.gHYyx8y5YzqKEZeYoMDqUOKejdSnY_AWhYZiSCMjR1V5')
      end
    end
  end

  describe '#pid' do
    let(:key_bytes) { '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' }

    context 'with a public key' do
      let(:key) { described_class.from_public_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k4.pid' do
        expect(key.pid).to eq('k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs')
      end
    end

    context 'with a secret key' do
      let(:key_bytes) do
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' \
          '1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
      end
      let(:key) { described_class.from_keypair(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k4.pid' do
        expect(key.pid).to eq('k4.pid.mCv5F34c3ALB7hzKEOQUsEBpj3CTArhbJzGyeeCCKWn1')
      end
    end
  end

  describe '#sid' do
    let(:key_bytes) { '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' }

    context 'with a public key' do
      let(:key) { described_class.from_public_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'raises an ArgumentError' do
        expect { key.sid }.to raise_error(ArgumentError, 'no private key available')
      end
    end

    context 'with a secret key' do
      let(:key_bytes) do
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' \
          '1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35'
      end
      let(:key) { described_class.from_keypair(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k4.sid' do
        expect(key.sid).to eq('k4.sid.gHYyx8y5YzqKEZeYoMDqUOKejdSnY_AWhYZiSCMjR1V5')
      end
    end
  end

  describe '#x25519_private_key' do
    let(:x25519_sk) { Paseto::Util.decode_hex('f824dc38b52b23ef0e27ddf4ddad7c0b144aefb46bc3ec57f053f9575224835d') }

    it 'converts the key to x25519 sk form' do
      expect(key.x25519_private_key.to_bytes).to eq(x25519_sk)
    end
  end

  describe '#x25519_public_key' do
    let(:x25519_pk) { Paseto::Util.decode_hex('012789e6eeea79a9edbefc1e4b71d3348aa94e1529cc1027fa7fb83b7ca2cf33') }

    it 'converts the key to x25519 pk form' do
      expect(key.x25519_public_key.to_bytes).to eq(x25519_pk)
    end
  end
end
