# frozen_string_literal: true

RSpec.describe Paseto::V4::Public do
  let(:sk_bytes) { Paseto::Util.decode_hex("68c16bc05a4d4d2bc537c8695cd562d1d1421a37a95eb3de9bdf8468e0da3448") }
  let(:vk_bytes) { Paseto::Util.decode_hex("f0d2091894bc5ed1cc9fa0ccbb17ce1512c8faa054b4b8f1882740562bacff13") }
  let(:key) { described_class.new(private_key: sk_bytes) }
  let(:key_pub) { described_class.new(public_key: vk_bytes) }

  describe ".generate" do
    it "returns a new instance" do
      expect(described_class.generate).to be_a(described_class)
    end
  end

  describe ".new" do
    it "succeds" do
      expect(key).to be_a(described_class)
    end

    it "errors when given both private and public keys" do
      expect do
        described_class.new(private_key: sk_bytes, public_key: vk_bytes)
      end.to raise_error(ArgumentError, "may not provide both private and public keys")
    end

    it "errors when provided no keys" do
      expect do
        described_class.new
      end.to raise_error(ArgumentError, "must provide one of private or public key")
    end

    context "when the public key is too long" do
      let(:vk_bytes) { Paseto::Util.decode_hex("f0d2091894bc5ed1cc9fa0ccbb17ce1512c8faa054b4b8f1882740562bacff1300") }

      it "raises a CryptoError" do
        expect { key_pub }.to raise_error(Paseto::CryptoError, "incorrect key size")
      end
    end

    context "when the public key is too short" do
      let(:vk_bytes) { Paseto::Util.decode_hex("f0d2091894bc5ed1cc9fa0ccbb17ce1512c8faa054b4b8f1882740562bacff13").chop }

      it "raises a CryptoError" do
        expect { key_pub }.to raise_error(Paseto::CryptoError, "incorrect key size")
      end
    end

    context "when the private key is too long" do
      let(:sk_bytes) { Paseto::Util.decode_hex("68c16bc05a4d4d2bc537c8695cd562d1d1421a37a95eb3de9bdf8468e0da344800") }

      it "raises a CryptoError" do
        expect { key }.to raise_error(Paseto::CryptoError, "incorrect key size")
      end
    end

    context "when the private key is too short" do
      let(:sk_bytes) { Paseto::Util.decode_hex("68c16bc05a4d4d2bc537c8695cd562d1d1421a37a95eb3de9bdf8468e0da3448").chop }

      it "raises a CryptoError" do
        expect { key }.to raise_error(Paseto::CryptoError, "incorrect key size")
      end
    end
  end

  describe "#version" do
    it { expect(key.version).to eq("v4") }
  end

  describe "#purpose" do
    it { expect(key.purpose).to eq("public") }
  end

  describe "#header" do
    it { expect(key.header).to eq("v4.public") }
  end

  describe "#public_key" do
    context "with only a public key" do
      it "equals to the provided public key" do
        expect(key_pub.public_key.to_s == vk_bytes).to be true
      end
    end

    context "with only a private key" do
      it "equals the calculated public key for the signing key" do
        expect(key.public_key.to_s == vk_bytes).to be true
      end
    end
  end

  describe "#sign" do
    subject(:token) { key.sign(message: "asdf", footer: "", implicit_assertion: "").to_s }

    it "returns the expected token" do
      expect(token).to eq("v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4")
    end

    context "with only a public key" do
      let(:key) { key_pub }

      it "raises an error" do
        expect { token }.to raise_error(ArgumentError, "no private key available")
      end
    end
  end

  describe "#verify" do
    subject(:verified) { key_pub.verify(token:) }

    let(:token) do
      Paseto::Token.parse("v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4")
    end

    it "returns the expected message" do
      expect(verified).to eq("asdf")
    end

    context "when the message is smaller than the signature size" do
      let(:token) { Paseto::Token.parse("v4.public.YXNkZg") }

      it "raises an error" do
        expect { verified }.to raise_error(Paseto::ParseError, "message too short")
      end
    end

    context "with an invalid signature" do
      let(:token) do
        Paseto::Token.parse("v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm66HVnen0PUYilrNMbXGlsyv7eyaA4")
      end

      it "raises an error" do
        expect { verified }.to raise_error(Paseto::InvalidSignature)
      end
    end
  end
end
