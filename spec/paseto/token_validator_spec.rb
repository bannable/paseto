# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::TokenValidator do
  let(:iss) { 'ban.paseto.test' }
  let(:aud) { 'test.paseto.ban' }
  let(:exp) { (Time.now + 5).iso8601 }
  let(:nbf) { (Time.now - 5).iso8601 }
  let(:iat) { (Time.now - 120).iso8601 }

  let(:claims) do
    {
      'iss' => 'ban.paseto.test',
      'aud' => 'test.paseto.ban',
      'exp' => exp,
      'nbf' => nbf,
      'iat' => iat
    }
  end

  describe '#validate' do
    subject(:validate) { described_class.new(iss:, aud:).validate(claims) }

    it { is_expected.to eq claims }

    context 'when a time field is not a valid format' do
      let(:exp) { Time.now.to_s }

      it 'raises ParseError' do
        expect { validate }.to raise_error(Paseto::ParseError, "invalid xmlschema format: \"#{exp}\"")
      end
    end

    context 'when the token is expired' do
      let(:exp) { (Time.now - 1).iso8601 }

      it 'raises ExpiredToken' do
        Timecop.freeze do
          expect { validate }.to raise_error(Paseto::ExpiredToken)
        end
      end
    end

    context 'when the token is inactive' do
      let(:nbf) { (Time.now + 1).iso8601 }

      it 'raises InactiveToken' do
        Timecop.freeze do
          expect { validate }.to raise_error(Paseto::InactiveToken)
        end
      end
    end

    context 'when the token is from another issuer' do
      let(:iss) { 'some.other.issuer' }

      it 'raises InvalidIssuer' do
        expect { validate }.to raise_error(Paseto::InvalidIssuer)
      end
    end

    context 'when the token is for a different audience' do
      let(:aud) { 'some.other.audience' }

      it 'raises InvalidAudience' do
        expect { validate }.to raise_error(Paseto::InvalidAudience)
      end
    end

    context 'when an issuer is not specified' do
      let(:iss) { nil }

      it 'succeeds' do
        expect { validate }.not_to raise_error
      end
    end

    context 'when an audience is not specified' do
      let(:aud) { nil }

      it 'succeeds' do
        expect { validate }.not_to raise_error
      end
    end

    context 'when the token is from the future' do
      let(:iat) { (Time.now + 1).iso8601 }

      it 'raises FutureTokenError' do
        expect { validate }.to raise_error(Paseto::FutureTokenError)
      end
    end
  end
end
