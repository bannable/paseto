# typed: false
# frozen_string_literal: true

RSpec.describe Paseto do
  it 'has a version number' do
    expect(described_class::VERSION).not_to be_nil
  end

  describe '.configure' do
    after { described_class.config.reset! }

    it 'yields the config' do
      expect do |blk|
        described_class.configure(&blk)
      end.to yield_with_args(described_class.config)
    end

    it 'updates the configuration via the block' do
      expect do
        described_class.configure { |c| c.decode.verify_exp = false }
      end.to change { described_class.config.decode.verify_exp }.from(true).to(false)
    end
  end
end
