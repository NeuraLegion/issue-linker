require "json"

module Issue::Linker
  struct BrightIssue
    include JSON::Serializable

    getter name : String
    getter id : String
    getter cwe : String
  end
end
