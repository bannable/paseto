module Paseto
  module Versions
    class BaseVersion
      def to_s
        self.class.name.to_s
      end
    end

    class V1 < BaseVersion; end
    class V2 < BaseVersion; end
    class V3 < BaseVersion; end
    class V4 < BaseVersion; end
  end
end