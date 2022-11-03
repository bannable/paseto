# frozen_string_literal: true

RSpec.describe Paseto::Key::AsymmetricPublic do
  let(:key_version) { "V4" }
  let(:key_material) { "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" }

  let(:key) { described_class.new(ikm: key_material, version: key_version) }

  describe "#valid_for?" do
    context "with a V4 key" do
    end
  end
end
