# frozen_string_literal: true

RSpec.describe Paseto::SymmetricKey do
  let(:key_version) { 'V4' }
  let(:key_material) { '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f' }

  let(:key) { Paseto::SymmetricKey.new(ikm: key_material, version: key_version) }

  describe '#valid_for?' do
    context 'with a V4 key' do
      it 'is true for version V4 and purpose local' do
        expect(key.valid_for?(version: 'V4', purpose: 'local')).to eq(true)
      end

      it 'is false for version V3 and purpose local' do
        expect(key.valid_for?(version: 'V3', purpose: 'local')).to eq(false)
      end

      it 'is false for version V4 and purpose remote' do
        expect(key.valid_for?(version: 'V4', purpose: 'remote')).to eq(false)
      end
    end
  end
end