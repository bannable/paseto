# frozen_string_literal: true

RSpec.describe Paseto::V4::Local do
  let(:key_material) { Paseto::Util.decode_hex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f") }
  let(:key) { described_class.new(ikm: key_material) }

  describe '#encrypt' do
    let(:message) { 'asdf' }
    let(:footer) { '' }
    let(:implicit_assertion) { '' }
    let(:token) { key.encrypt(message: message, footer: footer, implicit_assertion: implicit_assertion) }

    it { expect(token).to be_a(Paseto::Token) }
  end

  describe '#decrypt' do
    let(:message) { 'asdf' }
    let(:payload) { '9-aTBffMmDkgyBu8GcATCYCxHuqZoBFwfOMLL6tIXN42TFjR0oCCarn2XqAwimKez1oe3vFHjvrTr4YRSOlpXMR7mpk' }
    let(:footer) { '' }
    let(:implicit_assertion) { '' }
    subject { key.decrypt(payload: payload, footer: footer, implicit_assertion: implicit_assertion) }

    it 'does not error' do
      expect { subject }.not_to raise_error
    end
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
end
