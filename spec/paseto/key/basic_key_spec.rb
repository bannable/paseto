# frozen_string_literal: true

RSpec.describe Paseto::Key::BasicKey do
  let(:key_version) { Paseto::Versions::V4 }
  let(:key_material) { "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" }

  let(:key) { described_class.new(ikm: key_material, version: key_version) }

  describe "#valid_for?" do
    context "with a v4.local key" do
      it "is true for version V4 and purpose local" do
        expect(key.valid_for?(version: Paseto::Versions::V4, purpose: "local")).to be(true)
      end

      it "is false for version V3 and purpose local" do
        expect(key.valid_for?(version: Paseto::Versions::V3, purpose: "local")).to be(false)
      end

      it "is false for version V4 and purpose public" do
        expect(key.valid_for?(version: Paseto::Versions::V4, purpose: "public")).to be(false)
      end
    end
  end
end
