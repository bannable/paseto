# frozen_string_literal: true

RSpec.describe Paseto::V3::Public do
  subject(:crypt) { described_class.new(key: key_pem) }

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

  describe ".generate" do
    subject(:crypt) { described_class.generate }

    it { is_expected.to be_a(described_class) }

    it "has the expected group" do
      expect(crypt.key.group.curve_name).to eq("secp384r1")
    end
  end

  describe ".new" do
    it { is_expected.to be_a described_class }

    it "raises an error when the key is empty" do
      expect { described_class.new(key: "") }.to raise_error(Paseto::CryptoError, "invalid curve name")
    end

    it "raises an error when the key is the wrong type" do
      expect { described_class.new(key: nil) }.to raise_error(TypeError)
    end

    context "when the key is an invalid point" do
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

      it "raises an error" do
        expect { crypt }.to raise_error(Paseto::CryptoError, "EVP_PKEY_public_check: invalid private key")
      end
    end

    context "when the key is for a different EC group" do
      let(:key_pem) do
        <<~PRIME256V1
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIM1jvFNkK2dQc/zMb/qkGQfCGuhDNyYQauo6Foyn7BD9oAoGCCqGSM49
          AwEHoUQDQgAEc1hdwW24ZIra/e+FD7HQsBk0yir5g7bsoGtfy90X8/Se/E5IbkGD
          KF80qTx0c/IdyxoDwfvfuscl+9KFbNSiNg==
          -----END EC PRIVATE KEY-----
        PRIME256V1
      end

      it "raises an error" do
        expect { crypt }.to raise_error(Paseto::CryptoError, "EC_KEY_set_public_key: incompatible objects")
      end
    end
  end

  describe "#version" do
    it { expect(crypt.version).to eq("v3") }
  end

  describe "#purpose" do
    it { expect(crypt.purpose).to eq("public") }
  end

  describe "#header" do
    it { expect(crypt.header).to eq("v3.public") }
  end

  describe "#key" do
    it { expect(crypt.key).to be_a(OpenSSL::PKey::EC) }

    it "is the same as the input key" do
      expect(crypt.key.to_pem).to eq(key_pem)
    end
  end

  describe "#sign" do
    subject(:token) { crypt.sign(message: '{"foo":"bar"}', footer: "baz", implicit_assertion: "test") }

    it { is_expected.to be_a(Paseto::Token) }

    context "with only a public key" do
      let(:key_pem) do
        <<~PUBLIC_KEY
          -----BEGIN PUBLIC KEY-----
          MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmZZ5XSxUkU31FZSuQ6zzAY4IaGXT6b6f
          lqQMbw/me7x++1vEufDnSdLEjLCGNY16OWtexCsigBTd6sxblgEKfXUYKZ/L8snJ
          7RFBJ9CqUU8ZYKRZb7v1gkkLfK2JZb2M
          -----END PUBLIC KEY-----
        PUBLIC_KEY
      end

      it "raises an error" do
        expect { token }.to raise_error(ArgumentError, "no private key available")
      end
    end
  end

  describe "#verify" do
    subject(:verify) { crypt.verify(token:, implicit_assertion: "test") }

    let(:token) do
      Paseto::Token.parse(
        "v3.public.eyJmb28iOiJiYXIifVwJTfAz6v87ouQ0ctc8Iy6Cehuu0gAHWmXuKUQhIHOlNCWVLMjhksCAGd" \
        "j3a9QvHPwUxGD1O8DS0-RyBDpMsZc3NifE1RiiirauQT4scm4e2uuVpj7cd3VaO8_E961LVw.YmF6"
      )
    end

    it "returns the plain text" do
      expect(verify).to eq('{"foo":"bar"}')
    end

    context "with an invalid signature" do
      let(:token) do
        Paseto::Token.parse(
          "v3.public.eyJmb28iOiJiYXIifVwJTfAz6v87ouQ0ctc8Iy6Cehuu0gAHWmXuKUQhIHOlNCWVLMjhksCAGd" \
          "j3a9QvHPwUxGD1O8DS0-RyBDpMsZc3NifE1RiiirauQTAAAAAAAAAAVpj7cd3VaO8_E961LVw.YmF6"
        )
      end

      it "raises an error" do
        expect { verify }.to raise_error(Paseto::InvalidSignature)
      end
    end

    context "when the message is smaller than the signature size" do
      let(:token) { Paseto::Token.parse("v3.public.YXNkZg") }

      it "raises an error" do
        expect { verify }.to raise_error(Paseto::ParseError, "message too short")
      end
    end

    context "with a mismatched token type" do
      let(:token) do
        Paseto::Token.parse(
          "v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4"
        )
      end

      it "raises an error" do
        expect { verify }.to raise_error(Paseto::ParseError, "incorrect header for key type v3.public")
      end
    end
  end
end
