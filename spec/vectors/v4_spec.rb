# frozen_string_literal: true

RSpec.describe "PASETO v4 Test Vectors" do
  it '4-E-1', :sodium do
    nonce = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-2', :sodium do
    nonce = Paseto::Util.decode_hex('0000000000000000000000000000000000000000000000000000000000000000')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-3', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-4', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-5', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-6', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-7', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = %[{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[{"test-vector":"4-E-7"}]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-8', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[{"test-vector":"4-E-8"}]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-E-9', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24]
    payload = %[{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[arbitrary-string-that-isn't-json]
    ia = %[{"test-vector":"4-E-9"}]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end

  it '4-S-1', :sodium do
    pub = Paseto::V4::Public.new("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----")
    priv = Paseto::V4::Public.new("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----")
    tok = %[v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA]
    payload = %[{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[]
    ia = %[]
    token = Paseto::Token.parse(tok)

    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)
    expect(signed).to eq(tok)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end

  it '4-S-2', :sodium do
    pub = Paseto::V4::Public.new("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----")
    priv = Paseto::V4::Public.new("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----")
    tok = %[v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = %[{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[]
    token = Paseto::Token.parse(tok)

    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)
    expect(signed).to eq(tok)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end

  it '4-S-3', :sodium do
    pub = Paseto::V4::Public.new("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----")
    priv = Paseto::V4::Public.new("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----")
    tok = %[v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = %[{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}]
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[{"test-vector":"4-S-3"}]
    token = Paseto::Token.parse(tok)

    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)
    expect(signed).to eq(tok)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end

  it '4-F-1', :sodium do
    pub = Paseto::V4::Public.new("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----")
    priv = Paseto::V4::Public.new("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----")
    tok = %[v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlNdGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24]
    payload = nil
    footer = %[arbitrary-string-that-isn't-json]
    ia = %[{"test-vector":"4-F-1"}]
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
  end

  it '4-F-2', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn22Sp4gjCaUw0c7EH84ZSm_jN_Qr41MrgLNu5LIBCzUr1pn3Z-Wukg9h3ceplWigpoHaTLcwxj0NsI1vjTh67YB.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = nil
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[{"test-vector":"4-F-2"}]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

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

  it '4-F-3', :sodium do
    nonce = Paseto::Util.decode_hex('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v3.local.23e_2PiqpQBPvRFKzB0zHhjmxK3sKo2grFZRRLM-U7L0a8uHxuF9RlVz3Ic6WmdUUWTxCaYycwWV1yM8gKbZB2JhygDMKvHQ7eBf8GtF0r3K0Q_gF1PXOxcOgztak1eD1dPe9rLVMSgR0nHJXeIGYVuVrVoLWQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24]
    payload = nil
    footer = %[arbitrary-string-that-isn't-json]
    ia = %[{"test-vector":"4-F-3"}]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

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

  it '4-F-4', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQh]
    payload = nil
    footer = %[]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

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

  it '4-F-5', :sodium do
    nonce = Paseto::Util.decode_hex('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8')
    key = Paseto::Util.decode_hex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
    tok = %[v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ==.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9]
    payload = nil
    footer = %[{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}]
    ia = %[]

    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

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
