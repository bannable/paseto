# encoding: binary
# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Util do
  describe '.encode64' do
    it 'does not include padding' do
      expect(described_class.encode64('asdf')).to eq('YXNkZg')
    end

    it 'uses _ instead of /' do
      expect(described_class.encode64('Who am I?')).to eq('V2hvIGFtIEk_')
    end

    it 'uses - instead of +' do
      expect(described_class.encode64('<huff>')).to eq('PGh1ZmY-')
    end
  end

  describe '.decode64' do
    it 'does not require padding' do
      expect(described_class.decode64('YQ')).to eq('a')
    end

    it 'recognizes _ in place of /' do
      expect(described_class.decode64('V2hvIGFtIEk_')).to eq('Who am I?')
    end

    it 'recognizes - in place of +' do
      expect(described_class.decode64('PGh1ZmY-')).to eq('<huff>')
    end
  end

  describe '.le64' do
    it 'encodes 0 as an unsigned long long' do
      expect(described_class.le64(0)).to eq("\x00\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes a length as an unsigned long long' do
      expect(described_class.le64(10)).to eq("\x0A\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes larger lengths' do
      expect(described_class.le64(0xFFFE)).to eq("\xFE\xFF\x00\x00\x00\x00\x00\x00")
    end

    it 'raises when the input is larger than ULLONG_MAX' do
      expect { described_class.le64(0xFFFFFFFFFFFFFFFF + 1) }
        .to raise_error(ArgumentError, 'num too large')
    end

    it 'raises on negative inputs' do
      expect { described_class.le64(-1) }
        .to raise_error(ArgumentError, 'num must not be signed')
    end
  end

  describe '.pre_auth_encode' do
    it 'encodes zero parts correctly' do
      expect(described_class.pre_auth_encode).to eq(
        "\x00\x00\x00\x00\x00\x00\x00\x00"
      )
    end

    it 'encodes an empty string correctly' do
      expect(described_class.pre_auth_encode('')).to eq(
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      )
    end

    it 'encodes an arbitrary string correctly' do
      expect(described_class.pre_auth_encode('some str')).to eq(
        "\x01\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00some str"
      )
    end

    it 'encodes multiple parts correctly' do
      expect(described_class.pre_auth_encode('some', 'str')).to eq(
        "\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00some\x03\x00\x00\x00\x00\x00\x00\x00str"
      )
    end
  end

  describe '.constant_compare' do
    subject(:compare) { described_class.constant_compare(left, right) }

    context 'with equivelant strings' do
      let(:left) { 'foo' }
      let(:right) { 'foo' }

      it { is_expected.to be true }
    end

    context 'with different length strings' do
      let(:left) { 'foofoo' }
      let(:right) { 'foo' }

      it { is_expected.to be false }
    end

    context 'with different strings' do
      let(:left) { 'foo' }
      let(:right) { 'bar' }

      it { is_expected.to be false }
    end
  end
end
