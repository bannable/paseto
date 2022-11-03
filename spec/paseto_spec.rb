# frozen_string_literal: true

RSpec.describe Paseto do
  it "has a version number" do
    expect(Paseto::VERSION).not_to be nil
  end

  describe '.encode64' do
    it 'does not include padding' do
      expect(Paseto.encode64('a')).to eq('YQ')
      expect(Paseto.encode64('asdf')).to eq('YXNkZg')
    end

    it 'uses the urlsafe alphabet' do
      expect(Paseto.encode64('Who am I?')).to eq('V2hvIGFtIEk_')
      expect(Paseto.encode64('<huff>')).to eq('PGh1ZmY-')
    end
  end

  describe '.decode64' do
    it 'does not require padding' do
      expect(Paseto.decode64('YQ')).to eq('a')
    end

    it 'understands the urlsafe alphabet' do
      expect(Paseto.decode64('V2hvIGFtIEk_')).to eq('Who am I?')
      expect(Paseto.decode64('PGh1ZmY-')).to eq('<huff>')
    end
  end
end
