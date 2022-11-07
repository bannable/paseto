# frozen_string_literal: true

RSpec.describe Paseto::V4::Public do
  let(:sk1_bytes) { Paseto::Util.decode_hex("68c16bc05a4d4d2bc537c8695cd562d1d1421a37a95eb3de9bdf8468e0da3448") }
  let(:vk1_bytes) { Paseto::Util.decode_hex("f0d2091894bc5ed1cc9fa0ccbb17ce1512c8faa054b4b8f1882740562bacff13") }
  let(:sk2_bytes) { Paseto::Util.decode_hex("ea9ce393849031c4bce9dd1b3ba33eaf5c0a06189c81879f5e36e1b492a9b89f") }
  let(:vk2_bytes) { Paseto::Util.decode_hex("56cb25816b593aaa89a8034a99e08d2f00e9f98e454b8c59e795f6ec07fd7a0e")}
  let(:signing_key) { RbNaCl::SigningKey.new(sk1_bytes) }
  let(:verify_key) { RbNaCl::VerifyKey.new(vk1_bytes) }
  let(:other_signing) { RbNaCl::SigningKey.new(sk2_bytes) }
  let(:other_verify) { RbNacl::VerifyKey.new(vk2_bytes) }

  let(:sk_bytes) { sk1_bytes }
  let(:vk_bytes) { vk1_bytes }
  let(:key) { described_class.new(private_key: sk_bytes) }
  let(:key_pub) { described_class.new(public_key: vk_bytes) }

  let(:message) { 'asdf' }
  let(:footer) { '' }
  let(:implicit_assertion) { '' }

  describe ".generate" do
    it "returns a new instance" do
      expect(described_class.generate).to be_a(described_class)
    end
  end

  describe '.new' do
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

    context "when the public key is the wrong size" do
      context "too long" do
        let(:vk_bytes) { vk1_bytes + 'a' }

        it "raises a CryptoError" do
          expect { key_pub }.to raise_error(Paseto::CryptoError, "incorrect key size")
        end
      end

      context "too short" do
        let(:vk_bytes) { vk1_bytes.chop }

        it "raises a CryptoError" do
          expect { key_pub }.to raise_error(Paseto::CryptoError, "incorrect key size")
        end
      end
    end

    context "when the private key is the wrong size" do
      context "too long" do
        let(:sk_bytes) { sk1_bytes + 'a' }

        it "raises a CryptoError" do
          expect { key } .to raise_error(Paseto::CryptoError, "incorrect key size")
        end
      end

      context "too short" do
        let(:sk_bytes) { sk1_bytes.chop }

        it "raises a CryptoError" do
          expect { key } .to raise_error(Paseto::CryptoError, "incorrect key size")
        end
      end
    end
  end

  describe "#version" do
    it { expect(key.version).to eq("v4") }
    
    context "with only a public key" do
      it { expect(key_pub.version).to eq("v4") }
    end
  end

  describe "#purpose" do
    it { expect(key.purpose).to eq("public") }

    context "with only a public key" do
      it { expect(key_pub.purpose).to eq("public") }
    end
  end

  describe "#header" do
    it { expect(key.header).to eq("v4.public") }

    context "with only a public key" do
      it { expect(key_pub.header).to eq("v4.public") }
    end
  end

  describe "#public_key" do
    context "with only a public key" do
      it "equals to the provided public key" do
        expect(key_pub.public_key == verify_key).to be true
      end
    end

    context "with only a private key" do
      it "equals the calculated public key for the signing key" do
        expect(key.public_key == verify_key).to be true
      end
    end
  end

  # "asdf" signed with sk1 above
  let(:sk1_token_str) { "v4.public.YXNkZtafaHUveQPUAMlk9AWOmx9c1TWXcuE2x8FkhxIGd9iVc-subaSDKVf8nm65HVnen0PUYilrNMbXGlsyv7eyaA4" }

  # with footer "1234"
  let(:sk1_token_str_f) { "v4.public.YXNkZv34IKSFunw9LXch5Tls-FmSnQ7dXhEu4kR75pmx5yrJ8x2tX7aW6pFmFjkUKsUDwqJ-GGPgXZJgDE06Ma9uCAE.MTIzNA" }

  # with implicit assertion "false"
  let(:sk1_token_str_ia) { "v4.public.YXNkZqvCv_sax71-gsmJo1a_qA07mbxHiWSE7u4Xg-AZZnqaGuXEY967N3jhtIbd7t6DSLTJo8woMMj-kLUUUR5lTgM" }

  # with implicit assertion "false" and footer "1234"
  let(:sk1_token_str_f_ia) { "v4.public.YXNkZjWIMWWI0bvOSppx166nMfCioF7_Y8t6d7TZDNuoIpRFix3tgQSVr3b4FHiHVh0TgB2PcXSmWdZ1efwt9MTzSAw.MTIzNA" }

  # "asdf" signed with sk2 above
  let(:sk2_token_str) { "v4.public.YXNkZmbFFrQrHx1LcDHcMHDv2iZOKyOMSd1T3YK62Hq31sKpSE6obRtFLIzjyDHtO6xmdTNFSTJ-kTcvTNilHxf_VAw" }

  describe "#sign" do
    subject { key.sign(message: message, footer: footer, implicit_assertion: implicit_assertion).to_s }

    it "returns the expected token" do
      expect(subject).to eq(sk1_token_str)
    end

    context "with a footer" do
      let(:footer) { "1234" }

      it "returns the expected token" do
        expect(subject).to eq(sk1_token_str_f)
      end

      context "and an implicit assertion" do
        let(:implicit_assertion) { "false" }

        it "returns the expected token" do
          expect(subject).to eq(sk1_token_str_f_ia)
        end
      end
    end

    context "with an implicit assertion" do
      let(:implicit_assertion) { "false" }

      it "returns the expected token" do
        expect(subject).to eq(sk1_token_str_ia)
      end
    end

    context "with a different private key" do
      let(:sk_bytes) { sk2_bytes }

      it "returns a different signature" do
        expect(subject).to eq(sk2_token_str)
      end
    end

    context "with only a public key" do
      let(:key) { key_pub }

      it "raises an error" do
        expect { subject }.to raise_error(ArgumentError, "no private key available")
      end
    end
  end

  describe "#verify" do
    let(:token_str) { sk1_token_str }
    let(:token) { Paseto::Token.parse(token_str) }

    subject { key_pub.verify(token: token, implicit_assertion: implicit_assertion) }

    it "returns the expected message" do
      expect(subject).to eq(message)
    end

    context "when the message is smaller than the signature size" do
      let(:token_str) { "v4.public.YXNkZg"}

      it "raises an error" do
        expect { subject }.to raise_error(Paseto::ParseError, "message too short")
      end
    end

    context "with a footer" do
      let(:token_str) { sk1_token_str_f }

      it "returns the expected message" do
        expect(subject).to eq(message)
      end

      context "and an implicit assertion" do
        let(:implicit_assertion) { "false" }
        let(:token_str) { sk1_token_str_f_ia }

        it "returns the expected message" do
          expect(subject).to eq(message)
        end
      end
    end

    context "with an implicit assertion" do
      let(:implicit_assertion) { "false" }
      let(:token_str) { sk1_token_str_ia }

      it "returns the expected message" do
        expect(subject).to eq(message)
      end
    end

    context "with a different public key" do
      let(:vk_bytes) { vk2_bytes }

      it "raises an error" do
        expect { subject }.to raise_error(Paseto::InvalidSignature)
      end
    end
  end
end
