# typed: false
# frozen_string_literal: true

RSpec.describe Paseto do
  after { described_class.config.reset! }

  describe '.configure' do
    it 'yields the config' do
      expect do |blk|
        described_class.configure(&blk)
      end.to yield_with_args(described_class.config)
    end

    it 'updates the configuration via the block' do
      expect(described_class.config.decode.verify_exp).to eq true

      described_class.configure do |config|
        config.decode.verify_exp = false
      end

      expect(described_class.config.decode.verify_exp).to eq false
    end
  end
end
