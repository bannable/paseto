# frozen_string_literal: true

RSpec.describe Paseto::V4::Local do
  let(:key_material) { "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" }

  let(:key) { described_class.new(ikm: key_material) }

  describe '#encrypt' do
    let(:message) { 'asdf' }
    let(:footer) { '' }
    let(:implicit_assertion) { '' }
    let(:token) { key.encrypt(message: message, footer: footer, implicit_assertion: implicit_assertion) }

    it { expect(token).to be_a(Paseto::Token) }
  end

  describe '#decrypt' do
  end

  describe '#version' do
    it { expect(key.version).to eq('v4') }
  end

  describe '#purpose' do
    it { expect(key.purpose).to eq('local') }
  end

  describe '#header' do
    it { expect(key.header).to eq('v4.local') }
  end

  describe '#secret?' do
    it { expect(key.secret?).to be true }
  end

  describe "#valid_for?" do
    context "with a v4.local key" do
      it "is true for version v4 and purpose local" do
        expect(key.valid_for?(version: 'v4', purpose: "local")).to be(true)
      end

      it "is false for version v3" do
        expect(key.valid_for?(version: 'v3', purpose: "local")).to be(false)
      end

      it "is false for version V4" do
        expect(key.valid_for?(version: 'V3', purpose: "local")).to be(false)
      end

      it "is false for purpose public" do
        expect(key.valid_for?(version: 'v4', purpose: "public")).to be(false)
      end
    end
  end
end
