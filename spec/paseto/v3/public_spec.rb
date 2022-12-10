# typed: false
# frozen_string_literal: true

require 'shared_examples_for_keys'

RSpec.describe Paseto::V3::Public do
  subject(:key) { described_class.new(key: key_pem) }

  let(:key_pem) do
    # secp384r1 private key
    <<~PKEY
      -----BEGIN EC PRIVATE KEY-----
      MIGkAgEBBDCc5XO3mKvqE9kiiBFtlr9rP9t0bm3qM+l3NuMMA0rkcNa7iJ2A93BV
      DsZJ/mf0lKqgBwYFK4EEACKhZANiAATzxuXLt0DqMKEBVgGH4bhstxUkTJwIe66o
      08kVU1zCl4DI1zIxDKfwrFQc6fpiREWBNcHqrCieqkkERShKmNToujwIgBjSo2vg
      BP+3M0fMaefsef6sT4yFK4gVV/IGLKg=
      -----END EC PRIVATE KEY-----
    PKEY
  end
  let(:pub_pem) do
    <<~PUBLIC_KEY
      -----BEGIN PUBLIC KEY-----
      MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmZZ5XSxUkU31FZSuQ6zzAY4IaGXT6b6f
      lqQMbw/me7x++1vEufDnSdLEjLCGNY16OWtexCsigBTd6sxblgEKfXUYKZ/L8snJ
      7RFBJ9CqUU8ZYKRZb7v1gkkLfK2JZb2M
      -----END PUBLIC KEY-----
    PUBLIC_KEY
  end

  it_behaves_like 'a Key'

  describe '.generate' do
    subject(:key) { described_class.generate }

    it { is_expected.to be_a(described_class) }
  end

  describe '.new' do
    it { is_expected.to be_a described_class }

    it 'raises an error when the key is empty' do
      expect { described_class.new(key: '') }.to raise_error(Paseto::CryptoError, 'invalid curve name')
    end

    it 'raises an error when the key is the wrong type' do
      expect { described_class.new(key: nil) }.to raise_error(TypeError)
    end

    context 'when the key is an invalid point' do
      let(:key_pem) do
        <<~INVALID_KEY
          -----BEGIN EC PRIVATE KEY-----
          MIGkAgEBBDDA1Tm0m7YhkfeVpFuarAJYVlHp2tQj+1fOBiLa10t9E8TiQO/hVfxB
          vGaVEQwOheWgBwYFK4EEACKhZANiAASyGqmryZGqdpsq5gEDIfNvgC3AwSJxiBCL
          XKHBTFRp+tCezLDOK/6V8KK/vVGBJlGFW6/I7ahyXprxS7xs7hPA9iz5YiuqXlu+
          lbrIpZOz7b73hyQQCkvbBO/Avg+hPAk=
          -----END EC PRIVATE KEY-----
        INVALID_KEY
      end

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::InvalidKeyPair)
      end
    end

    context 'when the key is for a different EC group' do
      let(:key_pem) do
        <<~PRIME256V1
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIM1jvFNkK2dQc/zMb/qkGQfCGuhDNyYQauo6Foyn7BD9oAoGCCqGSM49
          AwEHoUQDQgAEc1hdwW24ZIra/e+FD7HQsBk0yir5g7bsoGtfy90X8/Se/E5IbkGD
          KF80qTx0c/IdyxoDwfvfuscl+9KFbNSiNg==
          -----END EC PRIVATE KEY-----
        PRIME256V1
      end

      it 'raises an error' do
        expect { key }.to raise_error(Paseto::LucidityError)
      end
    end
  end

  context 'when the private key value is 0' do
    let(:key_pem) do
      <<~P384_ZERO
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAACgBwYFK4EEACKhZANiAAR1NyMo52Luu+S/y8+MiarXkmVYSQiWVATe
        muQP0HxY7XotJuiG3cVuQyfs9PLyGNkvwE/u5dm+P9tFC+qzFSLSZrjYgxIg6lI+
        HyV/0Tep3t5rPGXmxevZ3MdjU8HqDsc=
        -----END EC PRIVATE KEY-----
      P384_ZERO
    end

    it 'raises an error' do
      expect { key }.to raise_error(Paseto::InvalidKeyPair)
    end
  end

  describe '#version' do
    it { expect(key.version).to eq('v3') }
  end

  describe '#purpose' do
    it { expect(key.purpose).to eq('public') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v3.public') }
  end

  describe '#public_to_pem' do
    let(:key_pem) { pub_pem }

    it 'equals the input PEM' do
      expect(key.public_to_pem).to eq key_pem
    end
  end

  describe '#private_to_pem' do
    it 'equals the input PEM' do
      expect(key.private_to_pem).to eq key_pem
    end

    context 'with only a public key' do
      let(:key_pem) { pub_pem }

      it 'raises an ArgumentError' do
        expect { key.private_to_pem }.to raise_error(ArgumentError, 'no private key available')
      end
    end
  end

  describe '#sign' do
    subject(:token) { key.sign(message: '{"foo":"bar"}', footer: 'baz', implicit_assertion: 'test') }

    it { is_expected.to be_a(Paseto::Token) }

    context 'with only a public key' do
      let(:key_pem) { pub_pem }

      it 'raises an error' do
        expect { token }.to raise_error(ArgumentError, 'no private key available')
      end
    end

    context 'when message is not UTF-8 encoded' do
      subject(:token) do
        key.sign(message: "\xC0")
      end

      it 'raises an error' do
        expect { token }.to raise_error(Paseto::ParseError, 'invalid message encoding, must be UTF-8')
      end
    end
  end

  describe '#verify' do
    subject(:verify) { key.verify(token: token, implicit_assertion: 'test') }

    let(:token) do
      Paseto::Token.parse(
        'v3.public.eyJmb28iOiJiYXIifVwJTfAz6v87ouQ0ctc8Iy6Cehuu0gAHWmXuKUQhIHOlNCWVLMjhksCAGd' \
        'j3a9QvHPwUxGD1O8DS0-RyBDpMsZc3NifE1RiiirauQT4scm4e2uuVpj7cd3VaO8_E961LVw.YmF6'
      )
    end

    it 'returns the plain text' do
      expect(verify).to eq('{"foo":"bar"}')
    end

    context 'when the payload is not UTF-8 encoded' do
      let(:token) do
        # Encodes \xC0, which is never valid in UTF8
        Paseto::Token.parse(
          'v3.public.wKEvP26BiSt090iZALN6NcQP3_icpUEx4mkKuEDkGNWEcg07jMY2__dZI1_h7Pnq_fpNJbS1MA' \
          'JgnC2yTK52s_w3KwgTdo0AAfl76RLuOV53YrMqZ_Cx6qe2ILU1fc25yA'
        )
      end

      it 'raises an error' do
        expect { verify }.to raise_error(Paseto::ParseError, 'invalid payload encoding')
      end
    end

    context 'with an invalid signature' do
      let(:token) do
        Paseto::Token.parse(
          'v3.public.eyJmb28iOiJiYXIifVwJTfAz6v87ouQ0ctc8Iy6Cehuu0gAHWmXuKUQhIHOlNCWVLMjhksCAGd' \
          'j3a9QvHPwUxGD1O8DS0-RyBDpMsZc3NifE1RiiirauQTAAAAAAAAAAVpj7cd3VaO8_E961LVw.YmF6'
        )
      end

      it 'raises an error' do
        expect { verify }.to raise_error(Paseto::InvalidSignature)
      end
    end

    context 'when the message is smaller than the signature size' do
      let(:token) { Paseto::Token.parse('v3.public.YXNkZg') }

      it 'raises an error' do
        expect { verify }.to raise_error(Paseto::ParseError, 'message too short')
      end
    end

    context 'with a mismatched token type' do
      let(:token) do
        Paseto::Token.parse(
          'v3.local.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4'
        )
      end

      it 'raises an error' do
        expect { verify }.to raise_error(Paseto::LucidityError)
      end
    end
  end

  describe '#to_paserk' do
    let(:key_pem) do
      <<~P384
        -----BEGIN EC PRIVATE KEY-----
        MD4CAQEEMHBxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeY
        mZqbnJ2en6AHBgUrgQQAIg==
        -----END EC PRIVATE KEY-----
      P384
    end

    context 'with a secret key' do
      it 'encodes to the expected k3.secret' do
        expect(key.paserk).to eq('k3.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6f')
      end
    end

    context 'with a secret key and requesting a public paserk' do
      it 'encodes to the expected k3.public' do
        expect(key.public_paserk).to eq('k3.public.AxqZCCGSmyX74eY91flGwJXKrQTl-5ATZYuDbsha8revply0Jy7BIKjXN1maDP1EJw')
      end
    end

    context 'with a public key' do
      let(:key_pem) do
        <<~P384
          -----BEGIN PUBLIC KEY-----
          MEYwEAYHKoZIzj0CAQYFK4EEACIDMgACcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaH
          iImKi4yNjo+QkZKTlJWWl5iZmpucnZ6f
          -----END PUBLIC KEY-----
        P384
      end

      it 'encodes to the expected k3.public' do
        expect(key.paserk).to eq('k3.public.AnBxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2enw')
      end
    end
  end

  describe '#id' do
    context 'with a public key' do
      let(:key_bytes) { '02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' }
      let(:key) { described_class.from_public_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k3.pid' do
        expect(key.id).to eq('k3.pid.mL4lGxNG7cz128frmpn83_76V9C7LmV2sHAMtJ8vIdwG')
      end
    end

    context 'with a secret key' do
      let(:key_bytes) { '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001' }
      let(:key) { described_class.from_scalar_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k3.sid' do
        expect(key.id).to eq('k3.sid.DjlX1m4BBFtsnbwzw1zv_x0yRcrZpsvdr_gIxh_hg_Rv')
      end
    end
  end

  describe '#pid' do
    context 'with a public key' do
      let(:key_bytes) { '02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' }
      let(:key) { described_class.from_public_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k3.pid' do
        expect(key.pid).to eq('k3.pid.mL4lGxNG7cz128frmpn83_76V9C7LmV2sHAMtJ8vIdwG')
      end
    end

    context 'with a secret key' do
      let(:key_bytes) { '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001' }
      let(:key) { described_class.from_scalar_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k3.pid' do
        expect(key.pid).to eq('k3.pid.6mfu-tuOAlvgfyirHYmFVDwVwkSxUB9vWJc2_cG_oCGG')
      end
    end
  end

  describe '#sid' do
    context 'with a public key' do
      let(:key_bytes) { '02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' }
      let(:key) { described_class.from_public_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'raises an ArgumentError' do
        expect { key.sid }.to raise_error(ArgumentError, 'no private key available')
      end
    end

    context 'with a secret key' do
      let(:key_bytes) { '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001' }
      let(:key) { described_class.from_scalar_bytes(Paseto::Util.decode_hex(key_bytes)) }

      it 'encodes to the expected k3.sid' do
        expect(key.sid).to eq('k3.sid.DjlX1m4BBFtsnbwzw1zv_x0yRcrZpsvdr_gIxh_hg_Rv')
      end
    end
  end
end
