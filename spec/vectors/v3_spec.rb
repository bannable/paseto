# frozen_string_literal: true

RSpec.describe "PASETO v3 Test Vectors" do
  it '3-E-1' do
    nonce = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-2' do
    nonce = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-3' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-4' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-5' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-6' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-7' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}]
    ia = %[{"test-vector":"3-E-7"}]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-8' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}]
    ia = %[{"test-vector":"3-E-8"}]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-E-9' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[arbitrary-string-that-isn't-json]
    ia = %[{"test-vector":"3-E-9"}]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce).to_s).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '3-S-1' do
    pub = Paseto::V3::Public.new(key: "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----")
    priv = Paseto::V3::Public.new(key: "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----")
    tok = %[v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph]
    payload = %[{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]
    token = Paseto::Token.parse(tok)

    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = priv.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end

  it '3-S-2' do
    pub = Paseto::V3::Public.new(key: "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----")
    priv = Paseto::V3::Public.new(key: "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----")
    tok = %[v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9]
    payload = %[{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}]
    ia = %[]
    token = Paseto::Token.parse(tok)

    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = priv.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end

  it '3-S-3' do
    pub = Paseto::V3::Public.new(key: "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----")
    priv = Paseto::V3::Public.new(key: "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----")
    tok = %[v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9]
    payload = %[{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}]
    ia = %[{"test-vector":"3-S-3"}]
    token = Paseto::Token.parse(tok)

    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = priv.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end

  it '3-F-1' do
    pub = Paseto::V3::Public.new(key: "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----")
    priv = Paseto::V3::Public.new(key: "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----")
    tok = %[v3.local.tthw-G1Da_BzYeMu_GEDp-IyQ7jzUCQHxCHRdDY6hQjKg6CuxECXfjOzlmNgNJ-WELjN61gMDnldG9OLkr3wpxuqdZksCzH9Ul16t3pXCLGPoHQ9_l51NOqVmMLbFVZOPhsmdhef9RxJwmqvzQ_Mo_JkYRlrNA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24]
    payload = nil
    footer = %[arbitrary-string-that-isn't-json]
    ia = %[{"test-vector":"3-F-1"}]
    token = Paseto::Token.parse(tok)

    expect do
      priv.sign(message: payload, footer: footer, implicit_assertion: ia)
    end.to raise_error(TypeError)

    message = begin
                pub.verify(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidSignature, Paseto::ParseError
                nil
              end
    expect(message).to be_nil

    message = begin
                priv.verify(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidSignature, Paseto::ParseError
                nil
              end
    expect(message).to be_nil
  end

  it '3-F-2' do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn1hbzIBD_EU54TYDTvsN9bbCU1QPo7FDeIhijkkcB9BrVH73XyM3Wwvu1pJaGCOEc0R5DVe9hb1ka1cYBd0goqVHt0NQ2NhPtILz4W36eCCqyU4uV6xDMeLI8ni6r3GnaY.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = nil
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[{"test-vector":"3-F-2"}]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect do
      local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)
    end.to raise_error(TypeError)

    message = begin
                local.decrypt(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidAuthenticator, Paseto::ParseError
                nil
              end
    expect(message).to be_nil
  end

  it '3-F-3' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.1JgN1UG8TFAYS49qsx8rxlwh-9E4ONUm3slJXYi5EibmzxpF0Q-du6gakjuyKCBX8TvnSLOKqCPu8Yh3WSa5yJWigPy33z9XZTJF2HQ9wlLDPtVn_Mu1pPxkTU50ZaBKblJBufRA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24]
    payload = nil
    footer = %[arbitrary-string-that-isn't-json]
    ia = %[{"test-vector":"3-F-3"}]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect do
      local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)
    end.to raise_error(TypeError)

    message = begin
                local.decrypt(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidAuthenticator, Paseto::ParseError
                nil
              end
    expect(message).to be_nil
  end

  it '3-F-4' do
    nonce = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeh]
    payload = nil
    footer = %[]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect do
      local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)
    end.to raise_error(TypeError)

    message = begin
                local.decrypt(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidAuthenticator, Paseto::ParseError
                nil
              end
    expect(message).to be_nil
  end

  it '3-F-5' do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc=.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9]
    payload = nil
    footer = %[{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}]
    ia = %[]

    begin
      token = Paseto::Token.parse(tok)
    rescue Paseto::UnsupportedToken # for 3-F-3 without RbNaCl
      # :nocov:
      skip('requires RbNaCl') unless Paseto.rbnacl?
      raise
      # :nocov:
    end
    local = Paseto::V3::Local.new(ikm: key)

    expect do
      local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)
    end.to raise_error(TypeError)

    message = begin
                local.decrypt(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidAuthenticator, Paseto::ParseError
                nil
              end
    expect(message).to be_nil
  end
end
