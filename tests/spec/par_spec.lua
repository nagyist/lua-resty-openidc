local test_support = require("test_support")
local http = require("socket.http")
require 'busted.runner'()

local function par_opts(extra)
  local opts = {
    use_par = true,
    discovery = {
      pushed_authorization_request_endpoint = "http://127.0.0.1/par",
    }
  }
  if extra then
    for k, v in pairs(extra) do
      opts[k] = v
    end
  end
  return opts
end

local function assert_par_endpoint_call_contains(s, case_insensitive)
  assert.error_log_contains("request body for pushed authorization request endpoint call: .*"
      .. s .. ".*", case_insensitive)
end

describe("when PAR is enabled", function()
  local status, headers

  setup(function()
    test_support.start_server({
      oidc_opts = par_opts()
    })

    local _
    _, status, headers = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("posts the authorization request parameters to the PAR endpoint", function()
    assert_par_endpoint_call_contains("response_type=code")
    assert_par_endpoint_call_contains("client_id=client_id")
    assert_par_endpoint_call_contains("scope=" .. test_support.urlescape_for_regex("openid email profile"))
    assert_par_endpoint_call_contains("redirect_uri="
        .. test_support.urlescape_for_regex("http://localhost/default/redirect_uri"), true)
    assert_par_endpoint_call_contains("state=")
    assert_par_endpoint_call_contains("nonce=")
  end)

  it("uses the configured client authentication for the PAR endpoint", function()
    assert_par_endpoint_call_contains("client_secret=client_secret")
  end)

  it("redirects to the authorization endpoint with the request_uri", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/authorize%?.*client_id=client_id.*"))
    assert.truthy(string.match(string.lower(headers["location"]), ".*request_uri="
        .. string.lower(test_support.urlescape_for_regex("urn:ietf:params:oauth:request_uri:test")) .. ".*"))
  end)

  it("does not expose full authorization parameters in the browser redirect", function()
    assert.falsy(string.match(headers["location"], ".*scope=.*"))
    assert.falsy(string.match(headers["location"], ".*nonce=.*"))
    assert.falsy(string.match(headers["location"], ".*redirect_uri=.*"))
    assert.falsy(string.match(headers["location"], ".*state=.*"))
  end)

  it("disables HTTP caching on the redirect response", function()
    assert.are.equals("no-cache, no-store, max-age=0", headers["cache-control"])
  end)
end)

describe("when PAR is enabled using client_secret_basic", function()
  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        discovery = {
          pushed_authorization_request_endpoint = "http://127.0.0.1/par",
          token_endpoint_auth_methods_supported = { "client_secret_basic" },
        }
      })
    })

    http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("uses a basic auth header for the PAR endpoint", function()
    assert.error_log_contains("par authorization header: Basic")
  end)

  it("does not send the client_secret in the PAR request body", function()
    assert.is_not.error_log_contains(
        "request body for pushed authorization request endpoint call: .*client_secret=client_secret.*")
  end)
end)

describe("when the PAR endpoint returns HTTP 200", function()
  local status, headers

  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        discovery = {
          pushed_authorization_request_endpoint = "http://127.0.0.1/par-200",
        }
      })
    })

    local _
    _, status, headers = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("accepts the response for interoperability", function()
    assert.are.equals(302, status)
    assert.truthy(string.find(headers["location"], "request_uri=", 1, true))
    assert.truthy(string.find(headers["location"], "test-200", 1, true))
  end)
end)

describe("when PAR is enabled using private_key_jwt", function()
  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        discovery = {
          pushed_authorization_request_endpoint = "http://127.0.0.1/par",
          token_endpoint_auth_methods_supported = { "private_key_jwt" },
        },
        token_endpoint_auth_method = "private_key_jwt",
        client_rsa_private_key = test_support.load("/spec/private_rsa_key.pem"),
      })
    })

    http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("sends a private_key_jwt client assertion to the PAR endpoint", function()
    assert_par_endpoint_call_contains("client_assertion=ey")
    assert_par_endpoint_call_contains(
        "client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient%-assertion%-type%%3Ajwt%-bearer")
  end)
end)

describe("when PAR is enabled with an unsupported client authentication method", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        pushed_authorization_request_endpoint_auth_method = "unsupported_auth",
      })
    })

    local _
    _, status = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("fails authentication", function()
    assert.are.equals(401, status)
  end)

  it("logs the unsupported PAR authentication method", function()
    assert.error_log_contains(
        "authenticate failed: configured value for pushed_authorization_request_endpoint_auth_method %(unsupported_auth%) is not supported")
  end)
end)

describe("when PAR is enabled but no endpoint is configured", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = {
        use_par = true,
      }
    })

    local _
    _, status = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("fails authentication", function()
    assert.are.equals(401, status)
  end)

  it("logs a clear error", function()
    assert.error_log_contains(
        "authenticate failed: no pushed authorization request endpoint URI")
  end)
end)

describe("when the PAR endpoint sends a 4xx status", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        discovery = {
          pushed_authorization_request_endpoint = "http://127.0.0.1/not-there",
        }
      })
    })

    local _
    _, status = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("fails authentication", function()
    assert.are.equals(401, status)
  end)

  it("logs the PAR response failure", function()
    assert.error_log_contains(
        "authenticate failed: response indicates failure, status=404,")
  end)
end)

describe("when the PAR endpoint does not return JSON", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        discovery = {
          pushed_authorization_request_endpoint = "http://127.0.0.1/par-invalid-json",
        }
      })
    })

    local _
    _, status = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("fails authentication", function()
    assert.are.equals(401, status)
  end)

  it("logs the JSON decoding failure", function()
    assert.error_log_contains("authenticate failed: JSON decoding failed")
  end)
end)

describe("when the PAR endpoint response omits request_uri", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = par_opts({
        discovery = {
          pushed_authorization_request_endpoint = "http://127.0.0.1/par-no-request-uri",
        }
      })
    })

    local _
    _, status = http.request({
      url = "http://127.0.0.1/default/t",
      redirect = false
    })
  end)

  teardown(test_support.stop_server)

  it("fails authentication", function()
    assert.are.equals(401, status)
  end)

  it("logs the missing request_uri", function()
    assert.error_log_contains(
        "authenticate failed: pushed authorization request response did not contain a request_uri")
  end)
end)
