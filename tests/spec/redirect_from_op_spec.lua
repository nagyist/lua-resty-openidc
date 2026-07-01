local http = require("socket.http")
local socket = require("socket")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

describe("when a redirect is received", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("without an active user session", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("but there's no session state found")
    end)
  end)
  describe("with bad state", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=X" .. state,
          headers = { cookie = cookie_header }
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("does not match state restored from session")
    end)
  end)
  describe("without state", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?code=foo",
          headers = { cookie = cookie_header }
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("unhandled request to the redirect_uri")
    end)
  end)
  describe("without code", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?state=" .. state,
          headers = { cookie = cookie_header }
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("unhandled request to the redirect_uri")
    end)
  end)
  describe("with all things set", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("/default/t", h.location)
    end)
  end)
end)

describe("when multiple authorization requests share the same session", function()
  test_support.start_server()
  teardown(test_support.stop_server)

  local _, _, first_headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local first_state = test_support.grab(first_headers, 'state')
  local first_cookie_header = test_support.extract_cookies(first_headers)

  local _, _, second_headers = http.request({
    url = "http://localhost/default/other",
    headers = { cookie = first_cookie_header },
    redirect = false
  })
  local second_state = test_support.grab(second_headers, 'state')
  local second_cookie_header = test_support.extract_cookies(second_headers)

  test_support.register_nonce(first_headers)
  local _, redirStatus, h = http.request({
        url = "http://localhost/default/redirect_uri?code=foo&state=" .. first_state,
        headers = { cookie = second_cookie_header },
        redirect = false
  })

  it("generates a new state for each authorization request", function()
    assert.are_not.equals(first_state, second_state)
  end)

  it("accepts the first authorization response", function()
    assert.are.equals(302, redirStatus)
  end)

  it("redirects to the first authorization request's original URI", function()
    assert.are.equals("/default/t", h.location)
  end)
end)

describe("when pending authorization states exceed the configured limit", function()
  test_support.start_server({
    oidc_opts = {
      authorization_state_max_number = 1
    }
  })
  teardown(test_support.stop_server)

  local _, _, first_headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local first_state = test_support.grab(first_headers, 'state')
  local first_cookie_header = test_support.extract_cookies(first_headers)

  local _, _, second_headers = http.request({
    url = "http://localhost/default/other",
    headers = { cookie = first_cookie_header },
    redirect = false
  })
  local second_state = test_support.grab(second_headers, 'state')
  local second_cookie_header = test_support.extract_cookies(second_headers)

  local _, first_redir_status = http.request({
    url = "http://localhost/default/redirect_uri?code=foo&state=" .. first_state,
    headers = { cookie = second_cookie_header },
    redirect = false
  })

  test_support.register_nonce(second_headers)
  local _, second_redir_status, second_redir_headers = http.request({
    url = "http://localhost/default/redirect_uri?code=foo&state=" .. second_state,
    headers = { cookie = second_cookie_header },
    redirect = false
  })

  it("rejects the oldest authorization response", function()
    assert.are.equals(401, first_redir_status)
  end)

  it("keeps the newest authorization response usable", function()
    assert.are.equals(302, second_redir_status)
    assert.are.equals("/default/other", second_redir_headers.location)
  end)
end)

describe("when pending authorization states exceed the configured limit in the same second", function()
  test_support.start_server({
    fixed_ngx_time = os.time(),
    oidc_opts = {
      authorization_state_max_number = 1
    }
  })
  teardown(test_support.stop_server)

  local _, _, first_headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local first_cookie_header = test_support.extract_cookies(first_headers)

  local _, _, second_headers = http.request({
    url = "http://localhost/default/other",
    headers = { cookie = first_cookie_header },
    redirect = false
  })
  local second_state = test_support.grab(second_headers, 'state')
  local second_cookie_header = test_support.extract_cookies(second_headers)

  test_support.register_nonce(second_headers)
  local _, second_redir_status, second_redir_headers = http.request({
    url = "http://localhost/default/redirect_uri?code=foo&state=" .. second_state,
    headers = { cookie = second_cookie_header },
    redirect = false
  })

  it("keeps the just-created authorization response usable", function()
    assert.are.equals(302, second_redir_status)
    assert.are.equals("/default/other", second_redir_headers.location)
  end)
end)

describe("when a pending authorization state has expired", function()
  test_support.start_server({
    oidc_opts = {
      authorization_state_expires_in = 0
    }
  })
  teardown(test_support.stop_server)

  local _, _, first_headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local first_state = test_support.grab(first_headers, 'state')
  local first_cookie_header = test_support.extract_cookies(first_headers)

  socket.sleep(1.1)

  local _, _, second_headers = http.request({
    url = "http://localhost/default/other",
    headers = { cookie = first_cookie_header },
    redirect = false
  })
  local second_state = test_support.grab(second_headers, 'state')
  local second_cookie_header = test_support.extract_cookies(second_headers)

  local _, first_redir_status = http.request({
    url = "http://localhost/default/redirect_uri?code=foo&state=" .. first_state,
    headers = { cookie = second_cookie_header },
    redirect = false
  })

  test_support.register_nonce(second_headers)
  local _, second_redir_status, second_redir_headers = http.request({
    url = "http://localhost/default/redirect_uri?code=foo&state=" .. second_state,
    headers = { cookie = second_cookie_header },
    redirect = false
  })

  it("rejects the expired authorization response", function()
    assert.are.equals(401, first_redir_status)
  end)

  it("keeps the fresh authorization response usable", function()
    assert.are.equals(302, second_redir_status)
    assert.are.equals("/default/other", second_redir_headers.location)
  end)
end)

describe("when the full login has been performed and the initial link is called", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local content_table = {}
  local _, status, _ = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
    sink = ltn12.sink.table(content_table)
  })
  it("no redirect occurs", function()
    assert.are.equals(200, status)
  end)
  it("the response is hello, world!", function()
    assert.are.equals("hello, world!\n", table.concat(content_table))
  end)
end)

describe("when the redirect_uri is specified as relative URI", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri = '/default/redirect_uri',
    },
  })
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("accessing the redirect_uri path with good parameters", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("/default/t", h.location)
    end)
  end)
  it("no deprecation warning is logged", function()
    assert.is_not.error_log_contains("using deprecated option `opts.redirect_uri_path`")
  end)
end)

describe("when the redirect_uri is specified via redirect_uri_path", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri_path = '/default/redirect_uri',
    },
    remove_oidc_config_keys = { 'redirect_uri' },
  })
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("accessing the redirect_uri path with good parameters", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("/default/t", h.location)
    end)
  end)
  it("a deprecation warning is logged", function()
    assert.error_log_contains("using deprecated option `opts.redirect_uri_path`")
  end)
end)

describe("when the redirect_uri and target-uri are specified as absolute URIs", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri = 'https://example.com/default-absolute/redirect_uri',
    },
  })
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default-absolute/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("accessing the redirect_uri path with good parameters", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default-absolute/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("http://localhost/default-absolute/t", h.location)
    end)
  end)
end)

describe("when redirect_uri and local_redirect_uri_path are specified", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri = 'https://example.com/foo/default-absolute/redirect_uri',
      local_redirect_uri_path = '/default-absolute/redirect_uri',
    },
  })
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default-absolute/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("accessing the redirect_uri path with good parameters", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default-absolute/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("http://localhost/default-absolute/t", h.location)
    end)
  end)
end)
