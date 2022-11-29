# typed: false
# frozen_string_literal: true

RSpec.describe Paseto::Verify do
  subject(:verify) do
    described_class.verify_claims(payload, options)
  end

  let(:options) do
    {
      verify_exp: true,
      verify_iat: true,
      verify_nbf: true,
      verify_aud: aud,
      verify_iss: iss,
      verify_sub: sub,
      verify_jti: jti
    }
  end

  let(:aud) { 'test.paseto.ban' }
  let(:exp) { (Time.now + 5).iso8601 }
  let(:iat) { (Time.now - 120).iso8601 }
  let(:iss) { 'ban.paseto.test' }
  let(:nbf) { (Time.now - 5).iso8601 }
  let(:sub) { 'test.test.test' }
  let(:jti) { '12345' }

  let(:payload) { claims }

  let(:claims) do
    {
      'aud' => aud,
      'exp' => exp,
      'iat' => iat,
      'iss' => iss,
      'nbf' => nbf,
      'sub' => sub,
      'jti' => jti
    }
  end

  it 'returns the claims on success' do
    expect(verify).to eq payload
  end

  context 'with the global configuration' do
    let(:options) { {} }

    it 'succeeds' do
      expect(verify).to eq payload
    end
  end

  context 'when verifying audience' do
    context 'with the wrong audience' do
      let(:payload) { claims.merge('aud' => 'foo') }

      it 'raises InvalidAudience' do
        expect { verify }.to raise_error(Paseto::InvalidAudience, "Invalid audience. Expected #{aud}, got foo")
      end
    end

    context 'with several permitted audiences' do
      let(:payload) { claims.merge('aud' => ['foo', aud]) }

      it 'succeeds' do
        expect(verify).to eq payload
      end
    end

    context 'with no audience' do
      let(:payload) { claims.except('aud') }

      it 'raises InvalidAudience' do
        expect { verify }.to raise_error(Paseto::InvalidAudience, "Invalid audience. Expected #{aud}, got <none>")
      end
    end
  end

  context 'when verifying expiration' do
    let(:payload) { claims.merge('exp' => (Time.now - 60).iso8601) }

    context 'with an expired token' do
      it 'raises ExpiredToken' do
        expect { verify }.to raise_error(Paseto::ExpiredToken, 'Expiry has passed')
      end

      it 'succeeds when verify_exp is false' do
        options[:verify_exp] = false
        expect(verify).to eq payload
      end
    end

    context 'with a malformed exp' do
      let(:payload) { claims.merge('exp' => Time.now.to_i.to_s) }

      it 'raises ExpiredToken' do
        Timecop.freeze do
          expect { verify }.to raise_error(Paseto::ExpiredToken, "Expiry not valid iso8601, got #{Time.now.to_i}")
        end
      end
    end

    context 'with no exp' do
      let(:payload) { claims.except('exp') }

      it 'raises ExpiredToken' do
        expect { verify }.to raise_error(Paseto::ExpiredToken, 'Expiry not valid iso8601, got <none>')
      end
    end
  end

  context 'when verifying iat' do
    context 'with an immature token' do
      let(:payload) { claims.merge('iat' => (Time.now + 60).iso8601) }

      it 'raises ImmatureToken' do
        expect { verify }.to raise_error(Paseto::ImmatureToken, 'Token is from the future')
      end
    end

    context 'with a malformed iat' do
      let(:payload) { claims.merge('iat' => Time.now.to_i.to_s) }

      it 'raises ImmatureToken' do
        Timecop.freeze do
          expect { verify }.to raise_error(Paseto::ImmatureToken, "IssuedAt not valid iso8601, got #{Time.now.to_i}")
        end
      end
    end

    context 'with no iat' do
      let(:payload) { claims.except('iat') }

      it 'raises ImmatureToken' do
        expect { verify }.to raise_error(Paseto::ImmatureToken, 'IssuedAt not valid iso8601, got <none>')
      end
    end
  end

  context 'when verifying iss' do
    context 'with the wrong issuer' do
      let(:payload) { claims.merge('iss' => 'someone.else.com') }

      it 'raises InvalidIssuer' do
        expect { verify }.to raise_error(Paseto::InvalidIssuer, %(Invalid issuer. Expected ["#{iss}"], got someone.else.com))
      end
    end

    context 'with several permitted issuers' do
      it 'succeeds' do
        options[:verify_iss] = ['example.com', iss]
        expect(verify).to eq payload
      end

      it 'converts symbols to strings' do
        options[:verify_iss] = iss.to_sym
        expect(verify).to eq payload
      end
    end

    context 'with a regexp' do
      it 'succeeds' do
        options[:verify_iss] = /\Aban.paseto.test\z/
        expect(verify).to eq payload
      end
    end

    context 'with a proc' do
      it 'succeeds when the proc is truthy' do
        options[:verify_iss] = ->(v) { v }
        expect(verify).to eq payload
      end

      it 'raises InvalidIssuer when the proc is false' do
        options[:verify_iss] = ->(_) { false }
        expect { verify }.to raise_error(Paseto::InvalidIssuer)
      end
    end

    context 'with no issuer' do
      let(:payload) { claims.except('iss') }

      it 'raises InvalidIssuer' do
        expect { verify }.to raise_error(Paseto::InvalidIssuer, %(Invalid issuer. Expected ["#{iss}"], got <none>))
      end
    end
  end

  context 'when verifying nbf' do
    context 'with a premature token' do
      let(:payload) { claims.merge('nbf' => (Time.now + 1).iso8601) }

      it 'raises InactiveToken' do
        Timecop.freeze do
          expect { verify }.to raise_error(Paseto::InactiveToken, 'Not yet active')
        end
      end

      it 'succeeds when verify_nbf is false' do
        options[:verify_nbf] = false
        expect(verify).to eq payload
      end
    end

    context 'with a malformed nbf' do
      let(:payload) { claims.merge('nbf' => Time.now.to_i.to_s) }

      it 'raises InactiveToken' do
        Timecop.freeze do
          expect { verify }.to raise_error(Paseto::InactiveToken, "NotBefore not valid iso8601, got #{Time.now.to_i}")
        end
      end
    end

    context 'with no exp' do
      let(:payload) { claims.except('nbf') }

      it 'raises InactiveToken' do
        expect { verify }.to raise_error(Paseto::InactiveToken, 'NotBefore not valid iso8601, got <none>')
      end
    end
  end

  context 'when verifying sub' do
    context 'with the incorrect subject' do
      let(:payload) { claims.merge('sub' => 'foo') }

      it 'raises InvalidSubject' do
        expect { verify }.to raise_error(Paseto::InvalidSubject, "Invalid subject. Expected #{sub}, got foo")
      end
    end

    context 'with no sub' do
      let(:payload) { claims.except('sub') }

      it 'raises InvalidSubject' do
        expect { verify }.to raise_error(Paseto::InvalidSubject, "Invalid subject. Expected #{sub}, got <none>")
      end
    end
  end

  context 'when verifying jti' do
    context 'with a proc' do
      it 'succeeds when truthy' do
        options[:verify_jti] = ->(v) { v }
        expect(verify).to eq payload
      end

      it 'raises InvalidTokenIdentifier when the proc is false' do
        options[:verify_jti] = ->(_) { false }
        expect { verify }.to raise_error(Paseto::InvalidTokenIdentifier, 'Invalid jti')
      end
    end

    context 'with no jti' do
      let(:payload) { claims.except('jti') }

      it 'raises InvalidTokenIdentifier' do
        expect { verify }.to raise_error(Paseto::InvalidTokenIdentifier, 'Missing jti')
      end
    end
  end
end
