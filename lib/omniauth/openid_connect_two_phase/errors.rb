module OmniAuth
  module OpenIDConnectTwoPhase
    class Error < RuntimeError; end
    class MissingCodeError < Error; end
  end
end
